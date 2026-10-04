// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package eval_test

import (
	"testing"

	provenancev1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	intoto "github.com/in-toto/attestation/go/v1"
	sourceprovenance "github.com/slsa-framework/source-tool/pkg/provenance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/slsa-framework/verifier/pkg/slsa/eval"
)

func newProvenanceV1WithSource(t *testing.T, source string) proto.Message {
	t.Helper()
	ext, err := structpb.NewStruct(map[string]any{"source": source})
	require.NoError(t, err)
	return &provenancev1.Provenance{
		BuildDefinition: &provenancev1.BuildDefinition{
			BuildType:          "https://example.com/buildType/v1",
			ExternalParameters: ext,
		},
		RunDetails: &provenancev1.RunDetails{
			Builder: &provenancev1.Builder{Id: "https://example.com/builder"},
		},
	}
}

func TestEvaluatorRegistersAllKnownTypes(t *testing.T) {
	t.Parallel()

	e, err := eval.NewEvaluator()
	require.NoError(t, err)

	for _, pt := range eval.KnownPredicateTypes() {
		assert.True(t, e.HasEnv(pt), "missing env for %s", pt)
	}
}

func TestEvaluateBuildProvenanceV1Pass(t *testing.T) {
	t.Parallel()

	e, err := eval.NewEvaluator()
	require.NoError(t, err)

	pred := newProvenanceV1WithSource(t, "git+https://example.com/repo")
	pass, err := e.Evaluate(
		eval.PredicateProvenanceV1,
		"predicate.buildDefinition.externalParameters.source == params.expected_source",
		pred,
		nil,
		map[string]any{"expected_source": "git+https://example.com/repo"},
	)
	require.NoError(t, err)
	assert.True(t, pass)
}

func TestEvaluateBuildProvenanceV1Fail(t *testing.T) {
	t.Parallel()

	e, err := eval.NewEvaluator()
	require.NoError(t, err)

	pred := newProvenanceV1WithSource(t, "git+https://example.com/different")
	pass, err := e.Evaluate(
		eval.PredicateProvenanceV1,
		"predicate.buildDefinition.externalParameters.source == params.expected_source",
		pred,
		nil,
		map[string]any{"expected_source": "git+https://example.com/repo"},
	)
	require.NoError(t, err)
	assert.False(t, pass)
}

func TestEvaluateUsesBuilderId(t *testing.T) {
	t.Parallel()

	e, err := eval.NewEvaluator()
	require.NoError(t, err)

	pred := newProvenanceV1WithSource(t, "git+https://example.com/repo")
	pass, err := e.Evaluate(
		eval.PredicateProvenanceV1,
		`predicate.runDetails.builder.id == "https://example.com/builder"`,
		pred,
		nil,
		nil,
	)
	require.NoError(t, err)
	assert.True(t, pass)
}

func TestEvaluateSubjectsAccessible(t *testing.T) {
	t.Parallel()

	e, err := eval.NewEvaluator()
	require.NoError(t, err)

	pred := newProvenanceV1WithSource(t, "x")
	subs := []*intoto.ResourceDescriptor{
		{Name: "main", Digest: map[string]string{"sha256": "deadbeef"}},
	}
	pass, err := e.Evaluate(
		eval.PredicateProvenanceV1,
		`subjects.size() == 1 && subjects[0].name == "main"`,
		pred,
		subs,
		nil,
	)
	require.NoError(t, err)
	assert.True(t, pass)
}

func TestEvaluateParamsListMembership(t *testing.T) {
	t.Parallel()

	e, err := eval.NewEvaluator()
	require.NoError(t, err)

	pred := newProvenanceV1WithSource(t, "x")
	pass, err := e.Evaluate(
		eval.PredicateProvenanceV1,
		`predicate.runDetails.builder.id in params.allowed_builders`,
		pred,
		nil,
		map[string]any{
			"allowed_builders": []string{
				"https://example.com/builder",
				"https://other.example.com/builder",
			},
		},
	)
	require.NoError(t, err)
	assert.True(t, pass)
}

func TestEvaluateSourceProvenance(t *testing.T) {
	t.Parallel()

	e, err := eval.NewEvaluator()
	require.NoError(t, err)

	pred := &sourceprovenance.SourceProvenancePred{
		RepoUri: "https://github.com/example/repo",
	}
	pass, err := e.Evaluate(
		eval.PredicateSourceProvenance,
		`predicate.repoUri == "https://github.com/example/repo"`,
		pred,
		nil,
		nil,
	)
	require.NoError(t, err)
	assert.True(t, pass)
}

func TestEvaluateUnsupportedPredicateType(t *testing.T) {
	t.Parallel()

	e, err := eval.NewEvaluator()
	require.NoError(t, err)

	_, err = e.Evaluate("https://example.com/unknown", "true", nil, nil, nil)
	assert.ErrorIs(t, err, eval.ErrUnsupportedPredicate)
}

func TestEvaluateCompileError(t *testing.T) {
	t.Parallel()

	e, err := eval.NewEvaluator()
	require.NoError(t, err)

	pred := newProvenanceV1WithSource(t, "x")
	_, err = e.Evaluate(eval.PredicateProvenanceV1, "this is not CEL @@", pred, nil, nil)
	assert.Error(t, err)
}

func TestEvaluateNonBoolResult(t *testing.T) {
	t.Parallel()

	e, err := eval.NewEvaluator()
	require.NoError(t, err)

	pred := newProvenanceV1WithSource(t, "x")
	_, err = e.Evaluate(eval.PredicateProvenanceV1, `"not a bool"`, pred, nil, nil)
	assert.ErrorIs(t, err, eval.ErrNonBooleanResult)
}

func TestRegistryNewPredicate(t *testing.T) {
	t.Parallel()

	for _, pt := range eval.KnownPredicateTypes() {
		msg, ok := eval.NewPredicate(pt)
		require.True(t, ok, "factory missing for %s", pt)
		require.NotNil(t, msg)
	}
	_, ok := eval.NewPredicate("https://example.com/unknown")
	assert.False(t, ok)
}

func TestIsKnownPredicateType(t *testing.T) {
	t.Parallel()

	assert.True(t, eval.IsKnownPredicateType(eval.PredicateProvenanceV1))
	assert.True(t, eval.IsKnownPredicateType(eval.PredicateSourceProvenance))
	assert.False(t, eval.IsKnownPredicateType("https://example.com/unknown"))
}
