// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
	"testing"

	"github.com/policylabs/attestation"
	"github.com/policylabs/collector/envelope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/verifier/pkg/slsa/controls"
)

func TestPartitionBuildTypeControls(t *testing.T) {
	t.Parallel()
	const predicateType = "https://slsa.dev/provenance/v1"
	stmt := loadTestStatement(t, "v1-build.intoto.json") // buildType https://example.com/buildType@v1
	check := func(params, optional []string) controls.Check {
		return controls.Check{
			PredicateType: predicateType, BuildTypes: []string{"https://example.com/buildType@v1"},
			Expression: "true", Parameters: params, OptionalParameters: optional,
		}
	}
	pure := &controls.Control{ID: "pure", Checks: []controls.Check{check(nil, nil)}}
	branch := &controls.Control{ID: "branch", Title: "Branch", Checks: []controls.Check{check([]string{"expected_branch"}, nil)}}
	tag := &controls.Control{ID: "tag", Title: "Tag", Checks: []controls.Check{check(nil, []string{"expected_tag"})}}
	other := &controls.Control{ID: "other", Checks: []controls.Check{{
		PredicateType: predicateType, BuildTypes: []string{"https://elsewhere.example.com/buildType"}, Expression: "true", Parameters: []string{"x"},
	}}}
	all := []*controls.Control{pure, branch, tag, other}
	ids := func(cs []*controls.Control) []string {
		out := make([]string, 0, len(cs))
		for _, c := range cs {
			out = append(out, c.ID)
		}
		return out
	}

	// No parameter set at all: the invocation is incomplete.
	_, _, err := partitionBuildTypeControls(&VerificationOptions{Params: map[string]any{}}, all, stmt)
	require.ErrorIs(t, err, ErrBuildTypeParamsUnset)
	var unset *BuildTypeParamsUnsetError
	require.ErrorAs(t, err, &unset)
	assert.Equal(t, "https://example.com/buildType@v1", unset.BuildType)
	require.Len(t, unset.Controls, 2, "controls whose check does not apply, or takes no parameters, are not listed")
	assert.Equal(t, "branch", unset.Controls[0].ID)
	assert.Equal(t, []string{"expected_branch"}, unset.Controls[0].Parameters)
	assert.Equal(t, "tag", unset.Controls[1].ID)
	assert.Equal(t, []string{"expected_tag"}, unset.Controls[1].OptionalParameters)
	assert.Contains(t, err.Error(), "expected_tag (optional)")
	assert.Contains(t, err.Error(), "--skip-buildtype-checks")

	// One expectation stated: everything runs; the unconfigured control
	// reports its own missing or optional parameter as usual.
	run, skipped, err := partitionBuildTypeControls(&VerificationOptions{Params: map[string]any{"expected_branch": "main"}}, all, stmt)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"pure", "other", "branch", "tag"}, ids(run))
	assert.Empty(t, skipped)

	// Skipping: unconfigured controls are reported as skipped, the rest run.
	run, skipped, err = partitionBuildTypeControls(&VerificationOptions{Params: map[string]any{}, SkipBuildTypeChecks: true}, all, stmt)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"pure", "other"}, ids(run))
	require.Len(t, skipped, 2)
	assert.Equal(t, StatusSkipped, skipped[0].Status)
	assert.Contains(t, skipped[0].Message, "expected_branch")

	// Nothing to partition.
	run, skipped, err = partitionBuildTypeControls(&VerificationOptions{}, nil, stmt)
	require.NoError(t, err)
	assert.Empty(t, run)
	assert.Empty(t, skipped)
}

// loadTestStatement parses a plain fixture for internal tests.
func loadTestStatement(t *testing.T, name string) attestation.Statement {
	t.Helper()
	envs, err := envelope.Parsers.ParseFiles([]string{"testdata/plain/" + name})
	require.NoError(t, err)
	require.Len(t, envs, 1)
	return envs[0].GetStatement()
}
