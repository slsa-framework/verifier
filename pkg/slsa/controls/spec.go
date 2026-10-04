// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package controls

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// specManifest is the schema of a catalog file under specs/: the list
// of control definitions the category comprises, each with the SLSA
// level that spec version assigns it (0 for unleveled categories like
// buildType).
type specManifest struct {
	Controls []specManifestEntry `yaml:"controls"`
}

type specManifestEntry struct {
	ID        string `yaml:"id"`
	SLSALevel int    `yaml:"slsaLevel,omitempty"`
}

// parseManifest decodes and structurally validates a spec manifest.
func parseManifest(data []byte) (*specManifest, error) {
	m := &specManifest{}
	if err := yaml.Unmarshal(data, m); err != nil {
		return nil, err
	}
	if len(m.Controls) == 0 {
		return nil, errors.New("manifest lists no controls")
	}
	for i, entry := range m.Controls {
		if entry.ID == "" {
			return nil, fmt.Errorf("manifest entry #%d: id is required", i)
		}
	}
	return m, nil
}

// specVersion is a parsed SLSA spec version (major.minor).
type specVersion struct {
	major, minor int
}

func (v specVersion) String() string {
	return fmt.Sprintf("%d.%d", v.major, v.minor)
}

// less orders spec versions by major, then minor.
func (v specVersion) less(other specVersion) bool {
	if v.major != other.major {
		return v.major < other.major
	}
	return v.minor < other.minor
}

// parseSpecVersion parses a SLSA spec version string: "1.2" or "v1.2".
func parseSpecVersion(value string) (specVersion, error) {
	trimmed := strings.TrimPrefix(strings.TrimSpace(value), "v")
	major, minor, found := strings.Cut(trimmed, ".")
	if !found {
		return specVersion{}, fmt.Errorf("invalid SLSA spec version %q (want major.minor, e.g. 1.2)", value)
	}
	majorNum, majErr := strconv.Atoi(major)
	minorNum, minErr := strconv.Atoi(minor)
	if majErr != nil || minErr != nil || majorNum < 0 || minorNum < 0 {
		return specVersion{}, fmt.Errorf("invalid SLSA spec version %q (want major.minor, e.g. 1.2)", value)
	}
	return specVersion{major: majorNum, minor: minorNum}, nil
}

// coreCategorySuffix is the last path segment of every core category.
const coreCategorySuffix = "core"

// SpecVersionOf returns the SLSA spec version segment of a core category
// ("source/1.2/core" > "1.2"). Non-core and unversioned categories rerturn
// an empty string.
func SpecVersionOf(cat Category) string {
	parts := strings.Split(string(cat), "/")
	if len(parts) != 3 || parts[2] != coreCategorySuffix {
		return ""
	}
	if _, err := parseSpecVersion(parts[1]); err != nil {
		return ""
	}
	return parts[1]
}

// coreVersions returns the spec versions for which the catalog holds core
// controls for the given track, sorted ascending.
func (c *Catalog) coreVersions(track Track) []specVersion {
	if c == nil {
		return nil
	}
	prefix := string(track) + "/"
	out := []specVersion{}
	for cat := range c.Controls {
		s := string(cat)
		if !strings.HasPrefix(s, prefix) || !strings.HasSuffix(s, "/"+coreCategorySuffix) {
			continue
		}
		raw := strings.TrimSuffix(strings.TrimPrefix(s, prefix), "/"+coreCategorySuffix)
		v, err := parseSpecVersion(raw)
		if err != nil {
			continue
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].less(out[j]) })
	return out
}

// ResolveCore returns the core category holding the track's controls for
// the requested SLSA spec version, along with the version it resolved to.
//
// Criteria carry forward across spec releases, so the newest catalog
// version at or below the requested one wins ("1.2" resolves to the
// build track's 1.0 catalog, whose criteria are unchanged since).
//
// An empty spec means "use the latest available". Requesting a version older
// than every catalog the track has returns an error.
func (c *Catalog) ResolveCore(track Track, spec string) (Category, string, error) {
	available := c.coreVersions(track)
	if len(available) == 0 {
		return "", "", fmt.Errorf("no core controls for track %q in the catalog", track)
	}
	if spec == "" {
		v := available[len(available)-1]
		return Category(fmt.Sprintf("%s/%s/%s", track, v, coreCategorySuffix)), v.String(), nil
	}
	requested, err := parseSpecVersion(spec)
	if err != nil {
		return "", "", err
	}
	for i := len(available) - 1; i >= 0; i-- {
		if !requested.less(available[i]) {
			v := available[i]
			return Category(fmt.Sprintf("%s/%s/%s", track, v, coreCategorySuffix)), v.String(), nil
		}
	}
	versions := make([]string, len(available))
	for i, v := range available {
		versions[i] = "v" + v.String()
	}
	return "", "", fmt.Errorf(
		"the %s track has no controls for SLSA spec v%s (defined since %s)",
		track, requested, strings.Join(versions, ", "),
	)
}
