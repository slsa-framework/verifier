// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package controls

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadEmbedded(t *testing.T) {
	t.Parallel()

	cat, err := LoadEmbedded()
	require.NoError(t, err)
	require.NotNil(t, cat)

	buildCore := cat.Get(BuildCore)
	require.NotEmpty(t, buildCore, "build/core should contain at least one control")

	var found *Control
	for _, c := range buildCore {
		if c.ID == "source-repo-match" {
			found = c
			break
		}
	}
	require.NotNil(t, found, "expected to find source-repo-match control")
	assert.Equal(t, "Source Repository Matches Expected URI", found.Title)
	// One check per supported build provenance version (v1, v0.2, v0.1).
	require.Len(t, found.Checks, 3)
	predicateTypes := make([]string, 0, len(found.Checks))
	for _, ck := range found.Checks {
		predicateTypes = append(predicateTypes, ck.PredicateType)
		assert.Contains(t, ck.Parameters, "expected_source", "every check requires expected_source")
	}
	assert.ElementsMatch(t, []string{
		"https://slsa.dev/provenance/v1",
		"https://slsa.dev/provenance/v0.2",
		"https://slsa.dev/provenance/v0.1",
	}, predicateTypes)
}

func TestLoadEmbeddedSourceCore(t *testing.T) {
	t.Parallel()

	cat, err := LoadEmbedded()
	require.NoError(t, err)
	require.NotEmpty(t, cat.Get(SourceCore), "source/core should contain at least one control")
}

func TestParseYAMLMultiDoc(t *testing.T) {
	t.Parallel()

	src := []byte(`id: a
title: A
checks:
  - predicateType: https://slsa.dev/provenance/v1
    expression: "true"
---
id: b
title: B
checks:
  - predicateType: https://slsa.dev/provenance/v1
    expression: "false"
`)

	out, err := parseYAML(src)
	require.NoError(t, err)
	require.Len(t, out, 2)
	assert.Equal(t, "a", out[0].ID)
	assert.Equal(t, "b", out[1].ID)
}

func TestParseYAMLSingleDoc(t *testing.T) {
	t.Parallel()

	src := []byte(`id: only
title: Only
checks:
  - predicateType: https://slsa.dev/provenance/v1
    expression: "true"
`)

	out, err := parseYAML(src)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, "only", out[0].ID)
}

func TestParseYAMLSkipsEmptyDocs(t *testing.T) {
	t.Parallel()

	src := []byte(`---
id: only
title: Only
checks:
  - predicateType: https://slsa.dev/provenance/v1
    expression: "true"
---
`)

	out, err := parseYAML(src)
	require.NoError(t, err)
	require.Len(t, out, 1)
}

func TestControlValidate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		ctrl    Control
		wantErr bool
	}{
		{
			name: "valid",
			ctrl: Control{
				ID:    "x",
				Title: "X",
				Track: "build",
				Checks: []Check{{
					PredicateType: "t",
					Expression:    "true",
				}},
			},
			wantErr: false,
		},
		{
			name: "missing id",
			ctrl: Control{
				Title: "X",
				Track: "build",
				Checks: []Check{{
					PredicateType: "t",
					Expression:    "true",
				}},
			},
			wantErr: true,
		},
		{
			name: "missing title",
			ctrl: Control{
				ID:    "x",
				Track: "build",
				Checks: []Check{{
					PredicateType: "t",
					Expression:    "true",
				}},
			},
			wantErr: true,
		},
		{
			name: "missing track",
			ctrl: Control{
				ID:    "x",
				Title: "X",
				Checks: []Check{{
					PredicateType: "t",
					Expression:    "true",
				}},
			},
			wantErr: true,
		},
		{
			name:    "no checks",
			ctrl:    Control{ID: "x", Title: "X", Track: "build"},
			wantErr: true,
		},
		{
			name: "check missing expression",
			ctrl: Control{
				ID:    "x",
				Title: "X",
				Track: "build",
				Checks: []Check{{
					PredicateType: "t",
				}},
			},
			wantErr: true,
		},
		{
			name: "check missing predicate type",
			ctrl: Control{
				ID:    "x",
				Title: "X",
				Track: "build",
				Checks: []Check{{
					Expression: "true",
				}},
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.ctrl.Validate()
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCategoryFromManifestPath(t *testing.T) {
	t.Parallel()

	cases := []struct {
		root, file string
		want       Category
	}{
		{"catalog/specs", "catalog/specs/build/1.0/core.yaml", BuildCore},
		{"catalog/specs", "catalog/specs/source/1.2/core.yaml", SourceCore},
		{"catalog/specs", "catalog/specs/build/buildType.yaml", BuildType},
		{"catalog/specs", "catalog/specs/source/1.3/core.yml", Category("source/1.3/core")},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, categoryFromManifestPath(tc.root, tc.file))
	}
}

func TestValidateCategory(t *testing.T) {
	t.Parallel()

	assert.NoError(t, validateCategory(BuildCore))
	assert.NoError(t, validateCategory(SourceCore))
	assert.NoError(t, validateCategory(BuildType))
	assert.NoError(t, validateCategory(Category("source/1.3/core")))
	require.Error(t, validateCategory(Category("source/core")), "unversioned core must be rejected")
	require.Error(t, validateCategory(Category("source/notaversion/core")))
	require.Error(t, validateCategory(Category("core")))
	assert.Error(t, validateCategory(Category("source/1.2/extra/core")))
}

func TestResolveCore(t *testing.T) {
	t.Parallel()

	cat, err := LoadEmbedded()
	require.NoError(t, err)

	// Empty spec resolves to the latest available version per track.
	got, ver, err := cat.ResolveCore(TrackBuild, "")
	require.NoError(t, err)
	assert.Equal(t, BuildCore, got)
	assert.Equal(t, "1.0", ver)

	got, ver, err = cat.ResolveCore(TrackSource, "")
	require.NoError(t, err)
	assert.Equal(t, SourceCore, got)
	assert.Equal(t, "1.2", ver)

	// Criteria carry forward: a newer spec resolves to the newest
	// catalog at or below it.
	got, ver, err = cat.ResolveCore(TrackBuild, "1.2")
	require.NoError(t, err)
	assert.Equal(t, BuildCore, got)
	assert.Equal(t, "1.0", ver)

	got, ver, err = cat.ResolveCore(TrackSource, "v1.2")
	require.NoError(t, err)
	assert.Equal(t, SourceCore, got)
	assert.Equal(t, "1.2", ver)

	// A spec predating the track's first catalog is an error: the
	// track did not exist in that release.
	_, _, err = cat.ResolveCore(TrackSource, "1.1")
	require.Error(t, err)

	// Malformed versions are errors.
	_, _, err = cat.ResolveCore(TrackBuild, "one.two")
	require.Error(t, err)
	_, _, err = cat.ResolveCore(TrackBuild, "1")
	assert.Error(t, err)
}

func TestSpecVersionOf(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "1.0", SpecVersionOf(BuildCore))
	assert.Equal(t, "1.2", SpecVersionOf(SourceCore))
	assert.Empty(t, SpecVersionOf(BuildType))
	assert.Empty(t, SpecVersionOf(Category("nonsense")))
}

// TestManifestLevelsMatchSpec pins the source 1.2 manifest's control →
// level mapping to the table in the SLSA v1.2 spec.
func TestManifestLevelsMatchSpec(t *testing.T) {
	t.Parallel()

	cat, err := LoadEmbedded()
	require.NoError(t, err)

	want := map[string]int{
		"source-repo-match":                   1,
		"source-branch-match":                 1,
		"source-tag-match":                    1,
		"source-tag-vsa-level-1":              1,
		"source-tag-vsa-level-2":              2,
		"source-tag-hygiene":                  2,
		"source-tag-vsa-level-3":              3,
		"source-tag-vsa-level-4":              4,
		"source-control-org-scs":              1,
		"source-control-scs-repo-id":          1,
		"source-control-scs-revision-id":      1,
		"source-control-scs-diff-display":     1,
		"source-control-org-access-control":   2,
		"source-control-org-safe-expunge":     2,
		"source-control-scs-history":          2,
		"source-control-scs-continuity":       2,
		"source-control-scs-identity":         2,
		"source-control-scs-provenance":       2,
		"source-control-org-continuity":       3,
		"source-control-scs-protected-refs":   3,
		"source-control-scs-two-party-review": 4,
	}
	got := map[string]int{}
	for _, c := range cat.Get(SourceCore) {
		got[c.ID] = c.SLSALevel
	}
	assert.Equal(t, want, got)
}
