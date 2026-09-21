// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package eval

import (
	"errors"
	"fmt"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
)

// ErrExpectedRepoHasRef is returned when an expected source repository
// carries a git ref (…@refs/heads/main): the repository expectation is
// about where the source lives, and the ref belongs to the branch and
// tag expectations.
var ErrExpectedRepoHasRef = errors.New("expected source repository must not carry a ref (@...)")

// RepoMatches reports whether the source URI recorded in a provenance
// denotes the expected repository. Provenance generators spell the
// source in several ways — git+https://github.com/org/repo@refs/tags/v1,
// https://github.com/org/repo, github.com/org/repo — and so do users, so
// both sides are normalized the way the original slsa-verifier did
// before comparing:
//
//   - a leading git+ is dropped; a scheme in expected must match the
//     recorded one, while a scheme-less expected (github.com/org/repo)
//     accepts any scheme;
//   - the ref (@…) is dropped from the recorded URI; expected must not
//     carry one, which returns ErrExpectedRepoHasRef;
//   - a trailing / or .git is dropped and the host compares
//     case-insensitively. The path keeps its case.
//
// An empty recorded URI never matches.
func RepoMatches(expected, actual string) (bool, error) {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return false, errors.New("expected source repository is empty")
	}
	if strings.Contains(expected, "@") {
		return false, fmt.Errorf("%w: %q", ErrExpectedRepoHasRef, expected)
	}
	want := parseRepoURI(expected)
	got := parseRepoURI(actual)
	if got.repo == "" || want.repo != got.repo {
		return false, nil
	}
	return want.scheme == "" || want.scheme == got.scheme, nil
}

// repoURI is a source URI reduced to the parts RepoMatches compares.
type repoURI struct {
	scheme string // without the git+ prefix; empty when the URI had none
	repo   string // host/path, with the host lowercased and the ref dropped
}

func parseRepoURI(uri string) repoURI {
	uri = strings.TrimPrefix(strings.TrimSpace(uri), "git+")
	var parsed repoURI
	if scheme, rest, ok := strings.Cut(uri, "://"); ok {
		parsed.scheme = strings.ToLower(scheme)
		uri = rest
	}
	// A ref follows the first @: git+https://host/org/repo@refs/tags/v1.
	uri, _, _ = strings.Cut(uri, "@")
	uri = strings.TrimSuffix(strings.TrimSuffix(uri, "/"), ".git")
	host, path, hasPath := strings.Cut(uri, "/")
	parsed.repo = strings.ToLower(host)
	if hasPath {
		parsed.repo += "/" + path
	}
	return parsed
}

// repoMatchesFunction exposes RepoMatches to CEL as
// repoMatches(expected, source). The source may be the URI string a
// generator recorded or a resource descriptor ({uri: …, digest: …}, as
// externalParameters.source is for several buildTypes), in which case
// its uri is compared. A null or missing source never matches; a
// malformed expectation is an evaluation error.
func repoMatchesFunction() cel.EnvOption {
	return cel.Function("repoMatches",
		cel.Overload("repoMatches_string_dyn",
			[]*cel.Type{cel.StringType, cel.DynType}, cel.BoolType,
			cel.BinaryBinding(func(expected, source ref.Val) ref.Val {
				e, ok := expected.Value().(string)
				if !ok {
					return types.NewErr("repoMatches: expected repository is not a string")
				}
				uri, err := sourceURI(source)
				if err != nil {
					return types.NewErr("repoMatches: %v", err)
				}
				matched, err := RepoMatches(e, uri)
				if err != nil {
					return types.NewErr("repoMatches: %v", err)
				}
				return types.Bool(matched)
			}),
		),
	)
}

// sourceURI extracts the URI from a CEL source value: the string itself,
// the uri field of a descriptor (map or message), or "" for null.
func sourceURI(source ref.Val) (string, error) {
	switch v := source.(type) {
	case types.String:
		return string(v), nil
	case types.Null:
		return "", nil
	case traits.Indexer:
		uri := v.Get(types.String("uri"))
		if types.IsError(uri) {
			return "", nil
		}
		s, ok := uri.(types.String)
		if !ok {
			return "", fmt.Errorf("source uri is %s, want a string", uri.Type().TypeName())
		}
		return string(s), nil
	default:
		return "", fmt.Errorf("source is %s, want a string or a resource descriptor", source.Type().TypeName())
	}
}
