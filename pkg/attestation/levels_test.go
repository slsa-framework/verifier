// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in     string
		prefix string
		n      int
		ok     bool
	}{
		{"SLSA_BUILD_LEVEL_3", "SLSA_BUILD", 3, true},
		{"SLSA_SOURCE_LEVEL_2", "SLSA_SOURCE", 2, true},
		{"SLSA_LEVEL_4", "SLSA", 4, true},
		{"SLSA_BUILD_LEVEL_0", "SLSA_BUILD", 0, true},
		{"FREEFORM", "", 0, false},
		{"", "", 0, false},
		{"SLSA_BUILD_LEVEL_three", "", 0, false},
		{"SLSA_BUILD_LEVEL_", "", 0, false},
	}
	for _, tc := range tests {
		p, n, ok := parseLevel(tc.in)
		assert.Equal(t, tc.ok, ok, "ok mismatch for %q", tc.in)
		if tc.ok {
			assert.Equal(t, tc.prefix, p, "prefix mismatch for %q", tc.in)
			assert.Equal(t, tc.n, n, "number mismatch for %q", tc.in)
		}
	}
}

func TestMatchesLevelAtOrAbove(t *testing.T) {
	t.Parallel()

	tests := []struct {
		want, observed string
		match          bool
	}{
		// At-or-above within the same track.
		{"SLSA_BUILD_LEVEL_3", "SLSA_BUILD_LEVEL_3", true},
		{"SLSA_BUILD_LEVEL_3", "SLSA_BUILD_LEVEL_4", true},
		{"SLSA_BUILD_LEVEL_3", "SLSA_BUILD_LEVEL_2", false},
		// Different track must not satisfy.
		{"SLSA_BUILD_LEVEL_3", "SLSA_SOURCE_LEVEL_4", false},
		{"SLSA_SOURCE_LEVEL_2", "SLSA_BUILD_LEVEL_3", false},
		// Legacy un-tracked form.
		{"SLSA_LEVEL_2", "SLSA_LEVEL_4", true},
		{"SLSA_LEVEL_4", "SLSA_LEVEL_2", false},
		// Legacy ≠ modern (different prefixes).
		{"SLSA_LEVEL_2", "SLSA_BUILD_LEVEL_3", false},
		// Freeform fallback: exact match only.
		{"CUSTOM_X", "CUSTOM_X", true},
		{"CUSTOM_X", "CUSTOM_Y", false},
		// Mixed canonical/freeform: exact-only.
		{"SLSA_BUILD_LEVEL_3", "FREEFORM", false},
		{"FREEFORM", "SLSA_BUILD_LEVEL_3", false},
	}
	for _, tc := range tests {
		got := matchesLevel(tc.want, tc.observed)
		assert.Equal(t, tc.match, got,
			"matchesLevel(want=%q, observed=%q) = %v, want %v",
			tc.want, tc.observed, got, tc.match)
	}
}
