// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
	"context"
	"testing"

	provenancev1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	"github.com/policylabs/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/slsa-framework/verifier/pkg/slsa/controls"
	"github.com/slsa-framework/verifier/pkg/slsa/eval"
)

func newProvV1StmtWithBuildType(t *testing.T, buildType string) *fakeStmt {
	t.Helper()
	ext, err := structpb.NewStruct(map[string]any{"source": "x"})
	require.NoError(t, err)
	return &fakeStmt{
		pType: attestation.PredicateType(eval.PredicateProvenanceV1),
		pred: &fakePredicate{
			pType: attestation.PredicateType(eval.PredicateProvenanceV1),
			parsed: &provenancev1.Provenance{
				BuildDefinition: &provenancev1.BuildDefinition{
					BuildType:          buildType,
					ExternalParameters: ext,
				},
				RunDetails: &provenancev1.RunDetails{
					Builder: &provenancev1.Builder{Id: "https://example.com/builder"},
				},
			},
		},
	}
}

// buildTypeControl is the sample control used in catalog/build/buildType
// (and equivalent inline here for tests).
func buildTypeControl(buildTypes []string) *controls.Control {
	return &controls.Control{
		ID:    "example-test-builder-id",
		Title: "Example Test Builder Identity",
		Checks: []controls.Check{{
			PredicateType: eval.PredicateProvenanceV1,
			BuildTypes:    buildTypes,
			Expression:    "predicate.runDetails.builder.id == params.expected_builder",
			Parameters:    []string{"expected_builder"},
		}},
	}
}

func TestRunControlsBuildTypeFilterMatches(t *testing.T) {
	t.Parallel()

	const bt = "https://example.com/test/buildType@v1"
	impl := newDefaultImpl(t)
	stmt := newProvV1StmtWithBuildType(t, bt)
	ctrls := []*controls.Control{buildTypeControl([]string{bt})}

	opts := &VerificationOptions{Params: map[string]any{"expected_builder": "https://example.com/builder"}}
	results, err := impl.RunControls(context.Background(), opts, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusPass, results[0].Status)
}

func TestRunControlsBuildTypeFilterSkipsNonMatch(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	stmt := newProvV1StmtWithBuildType(t, "https://example.com/different/buildType@v1")
	ctrls := []*controls.Control{buildTypeControl([]string{"https://example.com/test/buildType@v1"})}

	opts := &VerificationOptions{Params: map[string]any{"expected_builder": "https://example.com/builder"}}
	results, err := impl.RunControls(context.Background(), opts, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusSkipped, results[0].Status)
}

func TestRunControlsBuildTypeFilterEmptyAppliesToAny(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	stmt := newProvV1StmtWithBuildType(t, "https://anything.example.com")
	// No BuildTypes set → applies to any buildType, current core-control
	// behaviour preserved.
	ctrls := []*controls.Control{buildTypeControl(nil)}

	opts := &VerificationOptions{Params: map[string]any{"expected_builder": "https://example.com/builder"}}
	results, err := impl.RunControls(context.Background(), opts, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusPass, results[0].Status)
}

func TestRunControlsBuildTypeORMatchAcrossList(t *testing.T) {
	t.Parallel()

	const bt = "https://example.com/builder-b@v1"
	impl := newDefaultImpl(t)
	stmt := newProvV1StmtWithBuildType(t, bt)
	ctrls := []*controls.Control{buildTypeControl([]string{
		"https://example.com/builder-a@v1",
		bt,
		"https://example.com/builder-c@v1",
	})}

	opts := &VerificationOptions{Params: map[string]any{"expected_builder": "https://example.com/builder"}}
	results, err := impl.RunControls(context.Background(), opts, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
}

func TestSelectBuildTypeControlsBuildStatement(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	cat, err := controls.LoadEmbedded()
	require.NoError(t, err)

	stmt := newProvV1StmtWithBuildType(t, "https://example.com/test/buildType@v1")
	got := impl.SelectBuildTypeControls(&VerificationOptions{}, cat, stmt)
	assert.NotEmpty(t, got, "build statement should pull buildType controls")
}

func TestSelectBuildTypeControlsSourceStatement(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	cat, err := controls.LoadEmbedded()
	require.NoError(t, err)

	stmt := &fakeStmt{pType: attestation.PredicateType(eval.PredicateSourceProvenance)}
	got := impl.SelectBuildTypeControls(&VerificationOptions{}, cat, stmt)
	assert.Empty(t, got, "source statement should produce no buildType results")
}

func TestEmbeddedBuildTypeControlLoaded(t *testing.T) {
	t.Parallel()

	cat, err := controls.LoadEmbedded()
	require.NoError(t, err)
	bt := cat.Get(controls.BuildType)
	require.NotEmpty(t, bt, "embedded build/buildType catalog should contain at least one control")

	var found *controls.Control
	for _, c := range bt {
		if c.ID == "example-test-builder-id" {
			found = c
			break
		}
	}
	require.NotNil(t, found)
	require.Len(t, found.Checks, 1)
	assert.Equal(t, []string{"https://example.com/test/buildType@v1"}, found.Checks[0].BuildTypes)
}
