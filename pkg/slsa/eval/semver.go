// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package eval

import (
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"golang.org/x/mod/semver"
)

// VersionedTagMatches reports whether tag satisfies the versioned
// expectation expected, following semantic versioning the way the
// original slsa-verifier's --source-versioned-tag did:
//
//   - expected must be valid semver with a leading v (v1, v1.2, v1.2.3);
//   - the tag is canonicalized (v1.2 reads as v1.2.0) and must be valid
//     semver too; a leading refs/tags/ is accepted and dropped;
//   - the major version must match;
//   - the minor and patch versions are compared only when expected
//     states them, so v1 accepts every v1.x.y and v1.2 every v1.2.y;
//   - a prerelease is compared as part of the patch (v1.2.3-rc1 is not
//     v1.2.3), while build metadata is ignored, as semver requires.
//
// Anything that is not semver on either side does not match.
func VersionedTagMatches(expected, tag string) bool {
	expected = strings.TrimSpace(expected)
	if !semver.IsValid(expected) {
		return false
	}
	tag = strings.TrimPrefix(strings.TrimSpace(tag), "refs/tags/")
	canonical := semver.Canonical(tag)
	if !semver.IsValid(canonical) {
		return false
	}
	if semver.Major(expected) != semver.Major(canonical) {
		return false
	}
	expectedParts := strings.Split(strings.TrimSuffix(expected, semver.Build(expected)), ".")
	tagParts := strings.Split(canonical, ".")
	// Canonical always has three parts; expected has as many as it states.
	if len(expectedParts) > 1 && expectedParts[1] != tagParts[1] {
		return false
	}
	if len(expectedParts) > 2 && expectedParts[2] != tagParts[2] {
		return false
	}
	return true
}

// semverMatchesFunction exposes VersionedTagMatches to CEL as
// semverMatches(expected, tag).
func semverMatchesFunction() cel.EnvOption {
	return cel.Function("semverMatches",
		cel.Overload("semverMatches_string_string",
			[]*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
			cel.BinaryBinding(func(expected, tag ref.Val) ref.Val {
				e, ok := expected.Value().(string)
				if !ok {
					return types.NewErr("semverMatches: expected version is not a string")
				}
				t, ok := tag.Value().(string)
				if !ok {
					return types.NewErr("semverMatches: tag is not a string")
				}
				return types.Bool(VersionedTagMatches(e, t))
			}),
		),
	)
}
