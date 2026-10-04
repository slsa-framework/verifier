// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package eval_test

import (
	"testing"

	provenancev1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/slsa-framework/verifier/pkg/slsa/eval"
)

func TestRepoMatches(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		expected string
		actual   string
		want     bool
	}{
		{name: "identical", expected: "git+https://github.com/org/repo", actual: "git+https://github.com/org/repo", want: true},
		{name: "recorded ref is dropped", expected: "git+https://github.com/org/repo", actual: "git+https://github.com/org/repo@refs/tags/v1.0.0", want: true},
		{name: "scheme-less expectation", expected: "github.com/org/repo", actual: "git+https://github.com/org/repo@refs/heads/main", want: true},
		{name: "https expectation matches git+https", expected: "https://github.com/org/repo", actual: "git+https://github.com/org/repo", want: true},
		{name: "git+ expectation matches plain https", expected: "git+https://github.com/org/repo", actual: "https://github.com/org/repo", want: true},
		{name: "trailing slash", expected: "github.com/org/repo/", actual: "git+https://github.com/org/repo", want: true},
		{name: "trailing .git", expected: "github.com/org/repo", actual: "https://github.com/org/repo.git", want: true},
		{name: "host case", expected: "GitHub.com/org/repo", actual: "git+https://github.com/org/repo", want: true},
		{name: "scheme-less actual", expected: "github.com/org/repo", actual: "github.com/org/repo", want: true},
		{name: "path case is significant", expected: "github.com/Org/repo", actual: "git+https://github.com/org/repo", want: false},
		{name: "other repository", expected: "github.com/org/other", actual: "git+https://github.com/org/repo", want: false},
		{name: "other host", expected: "gitlab.com/org/repo", actual: "git+https://github.com/org/repo", want: false},
		{name: "stated scheme must match", expected: "http://github.com/org/repo", actual: "git+https://github.com/org/repo", want: false},
		{name: "prefix is not a match", expected: "github.com/org/repo", actual: "git+https://github.com/org/repo-fork", want: false},
		{name: "empty actual", expected: "github.com/org/repo", actual: "", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := eval.RepoMatches(tc.expected, tc.actual)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestRepoMatchesRejectsMalformedExpectation(t *testing.T) {
	t.Parallel()
	_, err := eval.RepoMatches("github.com/org/repo@refs/heads/main", "git+https://github.com/org/repo@refs/heads/main")
	require.ErrorIs(t, err, eval.ErrExpectedRepoHasRef)
	_, err = eval.RepoMatches("  ", "git+https://github.com/org/repo")
	require.Error(t, err)
}

// repoMatches in CEL accepts the recorded source as a string or as a
// resource descriptor, treats null as no source, and reports an
// unusable expectation as an evaluation error.
func TestRepoMatchesInCEL(t *testing.T) {
	t.Parallel()
	const predicateType = "https://slsa.dev/provenance/v1"
	ev, err := eval.NewEvaluator()
	require.NoError(t, err)

	externalParameters, err := structpb.NewStruct(map[string]any{
		"asString":     "git+https://github.com/org/repo@refs/heads/main",
		"asDescriptor": map[string]any{"uri": "git+https://github.com/org/repo@refs/heads/main", "digest": map[string]any{"gitCommit": "abc"}},
		"noURI":        map[string]any{"digest": map[string]any{"gitCommit": "abc"}},
		"asNull":       nil,
		"asNumber":     3,
	})
	require.NoError(t, err)
	predicate := &provenancev1.Provenance{BuildDefinition: &provenancev1.BuildDefinition{
		ExternalParameters:   externalParameters,
		ResolvedDependencies: []*intoto.ResourceDescriptor{{Uri: "git+https://github.com/org/dep@refs/heads/main"}},
	}}
	params := map[string]any{"expected_source": "github.com/org/repo"}

	for _, tc := range []struct {
		expr    string
		want    bool
		wantErr string
	}{
		{expr: `repoMatches(string(params.expected_source), predicate.buildDefinition.externalParameters.asString)`, want: true},
		{expr: `repoMatches(string(params.expected_source), predicate.buildDefinition.externalParameters.asDescriptor)`, want: true},
		{expr: `repoMatches(string(params.expected_source), predicate.buildDefinition.externalParameters.noURI)`, want: false},
		{expr: `repoMatches(string(params.expected_source), predicate.buildDefinition.externalParameters.asNull)`, want: false},
		{expr: `repoMatches(string(params.expected_source), predicate.buildDefinition.externalParameters.?missing.orValue(""))`, want: false},
		{expr: `repoMatches(string(params.expected_source), predicate.buildDefinition.resolvedDependencies[0])`, want: false},
		{expr: `repoMatches("github.com/org/dep", predicate.buildDefinition.resolvedDependencies[0])`, want: true},
		{expr: `repoMatches(string(params.expected_source), predicate.buildDefinition.externalParameters.asNumber)`, wantErr: "want a string or a resource descriptor"},
		{expr: `repoMatches("github.com/org/repo@refs/heads/main", predicate.buildDefinition.externalParameters.asString)`, wantErr: "must not carry a ref"},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			t.Parallel()
			got, err := ev.Evaluate(predicateType, tc.expr, predicate, nil, params)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
