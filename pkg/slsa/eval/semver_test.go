// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package eval_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/verifier/pkg/slsa/eval"
)

func TestVersionedTagMatches(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		expected string
		tag      string
		want     bool
	}{
		// The original slsa-verifier's table, tag v33.0.4.
		{"match tag", "v33.0.4", "v33.0.4", true},
		{"match minor", "v33.0", "v33.0.4", true},
		{"no match minor", "v33.1", "v33.0.4", false},
		{"no match minor with patch", "v33.1.0", "v33.0.4", false},
		{"match major", "v33", "v33.0.4", true},
		{"no match major greater", "v34", "v33.0.4", false},
		{"no match major greater with minor", "v34.0", "v33.0.4", false},
		{"no match major greater with minor and patch", "v34.0.4", "v33.0.4", false},
		{"no match major lower", "v32", "v33.0.4", false},
		{"no match major lower with minor", "v32.0", "v33.0.4", false},
		{"no match major lower with minor and patch", "v32.0.4", "v33.0.4", false},
		// Prerelease is part of the patch; build metadata is ignored.
		{"prerelease must match", "v1.2.3", "v1.2.3-rc1", false},
		{"prerelease matches itself", "v1.2.3-rc1", "v1.2.3-rc1", true},
		{"minor expectation accepts a prerelease", "v1.2", "v1.2.3-rc1", true},
		{"build metadata on the tag is ignored", "v1.2.3", "v1.2.3+20260101", true},
		{"build metadata on the expectation is ignored", "v1.2.3+abc", "v1.2.3", true},
		// A short tag is canonicalized.
		{"short tag reads as .0", "v1.2.0", "v1.2", true},
		{"short tag with a different patch expected", "v1.2.1", "v1.2", false},
		// Git refs are accepted.
		{"refs/tags prefix", "v1", "refs/tags/v1.9.2", true},
		// Not semver on either side never matches.
		{"expected without v", "1.2.3", "v1.2.3", false},
		{"tag without v", "v1.2.3", "1.2.3", false},
		{"expected is not a version", "main", "v1.2.3", false},
		{"tag is a branch ref", "v1", "refs/heads/main", false},
		{"empty", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, eval.VersionedTagMatches(tc.expected, tc.tag))
		})
	}
}

// The function is reachable from control expressions.
func TestSemverMatchesInCEL(t *testing.T) {
	t.Parallel()
	const predicateType = "https://slsa.dev/provenance/v1"
	predicate, ok := eval.NewPredicate(predicateType)
	require.True(t, ok)
	ev, err := eval.NewEvaluator()
	require.NoError(t, err)

	got, err := ev.Evaluate(predicateType, `semverMatches(string(params.expected_versioned_tag), "refs/tags/v33.0.4")`, predicate, nil, map[string]any{"expected_versioned_tag": "v33.0"})
	require.NoError(t, err)
	assert.True(t, got)

	got, err = ev.Evaluate(predicateType, `semverMatches(string(params.expected_versioned_tag), "refs/tags/v33.0.4")`, predicate, nil, map[string]any{"expected_versioned_tag": "v34"})
	require.NoError(t, err)
	assert.False(t, got)
}
