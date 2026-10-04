// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package controls

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/slsa-framework/verifier/pkg/slsa/eval"
)

//go:embed catalog
var catalogFS embed.FS

const (
	catalogRoot = "catalog"

	// definitionsDir holds the control definitions
	definitionsDir = "controls"
	// specsDir holds the per-spec-version manifests that
	// reference them and assign levels.
	specsDir = "specs"
)

// Category groups controls by their location in the embedded catalog tree.
// The string value matches the relative directory under catalogRoot. Core
// categories carry the SLSA spec version whose criteria they implement as
// their middle path segment (track/version/core). buildType categories
// are unversioned: they hold builder-specific custom controls, not
// spec-defined criteria.
type Category string

const (
	// BuildCore groups SLSA spec-defined controls applied to build
	// provenance, as defined since SLSA v1.0 (the criteria are unchanged
	// through v1.2). Prefer ResolveCore over naming the category directly.
	BuildCore Category = "build/1.0/core"

	// BuildType groups custom controls keyed to specific build types.
	BuildType Category = "build/buildType"

	// SourceCore groups SLSA spec-defined controls applied to SLSA source
	// attestations, introduced with the SLSA v1.2 source track. Prefer
	// ResolveCore over naming the category directly.
	SourceCore Category = "source/1.2/core"
)

// Catalog is a loaded set of controls grouped by category.
//
// PredicateTracks is a predicate-type to track mapping assembled at
// load time by walking every control's checks. A predicate type may
// appear under more than one track (because a VSA applicable to both
// build and source) when that happens, the verifier requires the
// caller to disambiguate via VerificationOptions.ForceTrack.
//
// This need to be exported for tests can construct synthetic catalogs.
type Catalog struct {
	Controls        map[Category][]*Control
	PredicateTracks map[string][]Track
}

// Get returns the controls registered under the given category.
func (c *Catalog) Get(cat Category) []*Control {
	if c == nil {
		return nil
	}
	return c.Controls[cat]
}

// TracksOf returns the tracks associated with the given predicate-type
// URI in this catalog. The empty slice means no loaded control references
// the predicate type. A slice of length > 1 means the predicate type is
// declared under multiple tracks and callers must use ForceTrack (or the
// CLI's --track flag) to disambiguate.
func (c *Catalog) TracksOf(predicateType string) []Track {
	if c == nil {
		return nil
	}
	return c.PredicateTracks[predicateType]
}

// BuildPredicateTracks is the exported wrapper used by tests to build a
// PredicateTracks map from a flat slice of controls. Production code
// uses the loader, which calls the same logic internally.
func BuildPredicateTracks(ctrls []*Control) map[string][]Track {
	return buildPredicateTracks(ctrls)
}

// LoadEmbedded loads the controls compiled into the binary.
func LoadEmbedded() (*Catalog, error) {
	return loadFromFS(catalogFS, catalogRoot)
}

// loadFromFS assembles a catalog from the layout rooted at
// root: control definitions under root/controls (parsed once, keyed by
// track and id) and spec-version manifests under root/specs. Each
// of the manifest's location is relative to root/specs (minus the .yaml
// extension) is the category its controls are placed under, its
// entries reference definitions by id and assign the SLSA level the
// spec version requires. After loading, the predicate-track mapping is
// assembled by walking every materialised control.
func loadFromFS(fsys fs.FS, root string) (*Catalog, error) {
	defs, err := loadDefinitions(fsys, path.Join(root, definitionsDir))
	if err != nil {
		return nil, err
	}

	cat := &Catalog{
		Controls:        map[Category][]*Control{},
		PredicateTracks: map[string][]Track{},
	}

	specsRoot := path.Join(root, specsDir)
	walkErr := fs.WalkDir(fsys, specsRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isYAML(p) {
			return nil
		}

		category := categoryFromManifestPath(specsRoot, p)
		if vErr := validateCategory(category); vErr != nil {
			return fmt.Errorf("invalid catalog layout at %s: %w", p, vErr)
		}
		data, readErr := fs.ReadFile(fsys, p)
		if readErr != nil {
			return fmt.Errorf("reading %s: %w", p, readErr)
		}
		manifest, parseErr := parseManifest(data)
		if parseErr != nil {
			return fmt.Errorf("parsing %s: %w", p, parseErr)
		}

		track, _, _ := strings.Cut(string(category), "/")
		for _, entry := range manifest.Controls {
			def := defs[Track(track)][entry.ID]
			if def == nil {
				return fmt.Errorf(
					"%s: control %q is not defined for track %q under %s/%s",
					p, entry.ID, track, root, definitionsDir)
			}
			// Copy the definition so the same control can hold different
			// levels in different spec versions.
			ctrl := *def
			ctrl.SLSALevel = entry.SLSALevel
			cat.Controls[category] = append(cat.Controls[category], &ctrl)
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	cat.PredicateTracks = buildPredicateTracks(flatten(cat.Controls))
	return cat, nil
}

// loadDefinitions walks the definitions tree and returns every control
// keyed by track and id. Definitions carry no SLSA level (the level is a
// property of a spec version defined by the manifests) and ids must
// be unique within a track.
func loadDefinitions(fsys fs.FS, root string) (map[Track]map[string]*Control, error) {
	defs := map[Track]map[string]*Control{}
	walkErr := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isYAML(p) {
			return nil
		}
		data, readErr := fs.ReadFile(fsys, p)
		if readErr != nil {
			return fmt.Errorf("reading %s: %w", p, readErr)
		}
		ctrls, parseErr := parseYAML(data)
		if parseErr != nil {
			return fmt.Errorf("parsing %s: %w", p, parseErr)
		}
		for _, ctrl := range ctrls {
			if vErr := ctrl.Validate(); vErr != nil {
				return fmt.Errorf("invalid control in %s: %w", p, vErr)
			}
			if vErr := validateTrack(ctrl); vErr != nil {
				return fmt.Errorf("invalid control in %s: %w", p, vErr)
			}
			if ctrl.SLSALevel != 0 {
				return fmt.Errorf(
					"invalid control in %s: %q sets slsaLevel — definitions carry no level, levels are assigned by the manifests under %s",
					p, ctrl.ID, specsDir)
			}
			track := Track(ctrl.Track)
			if defs[track] == nil {
				defs[track] = map[string]*Control{}
			}
			if _, dup := defs[track][ctrl.ID]; dup {
				return fmt.Errorf("%s: duplicate control id %q for track %q", p, ctrl.ID, track)
			}
			defs[track][ctrl.ID] = ctrl
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return defs, nil
}

func isYAML(p string) bool {
	return strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")
}

// flatten returns every control across every category as a single slice.
func flatten(byCategory map[Category][]*Control) []*Control {
	out := make([]*Control, 0)
	for _, group := range byCategory {
		out = append(out, group...)
	}
	return out
}

// buildPredicateTracks walks ctrls and returns the pred-type to
// tracks map. A predicate appearing under more than one track is
// allowed and its disambiguation happens later using VerificationOptions.ForceTrack.
// This is used both for the embedded catalog assembly and (in tests) for
// user-supplied control sets.
func buildPredicateTracks(ctrls []*Control) map[string][]Track {
	out := map[string][]Track{}
	for _, ctrl := range ctrls {
		track := Track(ctrl.Track)
		for _, ck := range ctrl.Checks {
			if !slices.Contains(out[ck.PredicateType], track) {
				out[ck.PredicateType] = append(out[ck.PredicateType], track)
			}
		}
	}
	return out
}

// categoryFromManifestPath returns the manifest file's path relative to
// the specs root, minus the YAML extension, used as the Category key
// (specs/source/1.2/core.yaml >> "source/1.2/core").
func categoryFromManifestPath(root, file string) Category {
	rel := strings.TrimPrefix(strings.TrimPrefix(file, root), "/")
	return Category(strings.TrimSuffix(rel, path.Ext(rel)))
}

// validateCategory rejects catalog directories that don't match the
// expected layout:
// spec-defined core controls live under track/specVersion/core
// buildType controls under track/buildType
//
// A YAML dropped anywhere else (eg in an unversioned track/core) would
// silently never resolve, so it's a load error.
func validateCategory(cat Category) error {
	parts := strings.Split(string(cat), "/")
	if len(parts) == 2 && parts[1] == "buildType" {
		return nil
	}
	if len(parts) == 3 && parts[2] == coreCategorySuffix {
		if _, err := parseSpecVersion(parts[1]); err != nil {
			return fmt.Errorf("category %q: %w", cat, err)
		}
		return nil
	}
	return fmt.Errorf(
		"category %q does not match <track>/<specVersion>/core or <track>/buildType", cat)
}

// validateTrack performs the per-control track checks: the track must
// be a known value and every check's predicateType must be registered
// in the eval package (so we have a proto to parse it into and a CEL
// env to run against). Cross-control track consistency happens at the
// catalog level via assemblePredicateTracks.
func validateTrack(c *Control) error {
	track := Track(c.Track)
	switch track {
	case TrackBuild, TrackSource:
	default:
		return fmt.Errorf("control %q: track must be %q or %q (got %q)",
			c.ID, TrackBuild, TrackSource, c.Track)
	}
	for i, ck := range c.Checks {
		if !eval.IsKnownPredicateType(ck.PredicateType) {
			return fmt.Errorf("control %q check #%d: predicateType %q is not a registered SLSA predicate",
				c.ID, i, ck.PredicateType)
		}
	}
	return nil
}

// parseYAML decodes a multi-document YAML stream into a slice of controls.
// Empty documents (e.g. trailing `---` markers) are skipped.
func parseYAML(data []byte) ([]*Control, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var out []*Control
	for {
		var c Control
		if err := dec.Decode(&c); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if c.ID == "" && c.Title == "" && len(c.Checks) == 0 {
			continue
		}
		out = append(out, &c)
	}
	return out, nil
}
