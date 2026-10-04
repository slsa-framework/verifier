// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"strconv"
	"strings"
)

// levelAnchor is the substring separating the track prefix from the
// numeric level in canonical SLSA level strings. Same anchor for the
// modern per-track form (SLSA_BUILD_LEVEL_3, SLSA_SOURCE_LEVEL_2)
// and the legacy un-tracked form (SLSA_LEVEL_2).
const levelAnchor = "_LEVEL_"

// parseLevel splits a SLSA level string into its track prefix and
// numeric level. Examples:
//
//	"SLSA_BUILD_LEVEL_3"  → "SLSA_BUILD", 3, true
//	"SLSA_SOURCE_LEVEL_2" → "SLSA_SOURCE", 2, true
//	"SLSA_LEVEL_4"        → "SLSA", 4, true
//	"FREEFORM"            → "", 0, false
//
// Returns ok=false for strings that don't match the canonical
// "<prefix>_LEVEL_<N>" shape; callers can then fall back to
// exact-match comparison.
func parseLevel(s string) (prefix string, n int, ok bool) {
	idx := strings.LastIndex(s, levelAnchor)
	if idx < 0 {
		return "", 0, false
	}
	num, err := strconv.Atoi(s[idx+len(levelAnchor):])
	if err != nil {
		return "", 0, false
	}
	return s[:idx], num, true
}

// matchesLevel reports whether observed satisfies the want level
// requirement. For canonical SLSA level strings, "satisfies" means
// same track prefix and observed.number >= want.number — so
// SLSA_BUILD_LEVEL_4 satisfies a want of SLSA_BUILD_LEVEL_3, but
// SLSA_SOURCE_LEVEL_4 does NOT (different track).
//
// When either side is not a canonical level string, the comparison
// degrades to exact string equality. This keeps freeform values
// (e.g. custom levels a producer might emit) safe — they only
// match themselves, never neighbouring numbers.
func matchesLevel(want, observed string) bool {
	wp, wn, wok := parseLevel(want)
	if !wok {
		return want == observed
	}
	op, on, ook := parseLevel(observed)
	if !ook {
		return want == observed
	}
	return wp == op && on >= wn
}
