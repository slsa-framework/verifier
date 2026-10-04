// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
	"context"
	"path/filepath"
	"testing"

	provenancev1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	"github.com/policylabs/collector/envelope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/slsa-framework/verifier/pkg/slsa/controls"
	"github.com/slsa-framework/verifier/pkg/slsa/eval"
)

// fullV1Stmt builds a v1 provenance fixture populated with all the
// fields the new L2/L3 controls inspect.
func fullV1Stmt(t *testing.T) *fakeStmt {
	t.Helper()
	ext, err := structpb.NewStruct(map[string]any{"source": "git+https://example.com/repo"})
	require.NoError(t, err)
	return &fakeStmt{
		pType: attestation.PredicateType(eval.PredicateProvenanceV1),
		pred: &fakePredicate{
			pType: attestation.PredicateType(eval.PredicateProvenanceV1),
			parsed: &provenancev1.Provenance{
				BuildDefinition: &provenancev1.BuildDefinition{
					BuildType:          "https://example.com/buildType@v1",
					ExternalParameters: ext,
					ResolvedDependencies: []*intoto.ResourceDescriptor{
						{Uri: "git+https://example.com/dep", Digest: map[string]string{"sha256": "abc"}},
					},
				},
				RunDetails: &provenancev1.RunDetails{
					Builder: &provenancev1.Builder{Id: "https://example.com/builder"},
					Metadata: &provenancev1.BuildMetadata{
						InvocationId: "build-1234",
					},
				},
			},
		},
	}
}

// findEmbedded returns the embedded core control with id, or fails the
// test if it isn't present.
// loadPlainFixture parses a plain in-toto fixture from testdata/plain.
func loadPlainFixture(t *testing.T, name string) attestation.Statement {
	t.Helper()
	envs, err := envelope.Parsers.ParseFiles([]string{filepath.Join("testdata", "plain", name)})
	require.NoError(t, err, "parsing fixture %s", name)
	require.Len(t, envs, 1)
	stmt := envs[0].GetStatement()
	require.NotNil(t, stmt)
	return stmt
}

func findEmbedded(t *testing.T, id string) *controls.Control {
	t.Helper()
	cat, err := controls.LoadEmbedded()
	require.NoError(t, err)
	for _, c := range cat.Get(controls.BuildCore) {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("embedded control %q not found in build/core", id)
	return nil
}

func TestEmbeddedL2L3ControlsLoad(t *testing.T) {
	t.Parallel()

	cases := []struct {
		id    string
		level int
	}{
		{"source-repo-match", 1},
		{"builder-id-trusted", 2},
		{"provenance-l2-complete", 2},
		{"provenance-has-invocation-id", 3},
		{"provenance-has-resolved-dependencies", 3},
	}
	for _, tc := range cases {
		c := findEmbedded(t, tc.id)
		assert.Equal(t, tc.level, c.SLSALevel, "%s slsaLevel", tc.id)
		require.NotEmpty(t, c.Checks)
		assert.Equal(t, eval.PredicateProvenanceV1, c.Checks[0].PredicateType)
	}
}

func TestBuilderTrustedPasses(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	stmt := fullV1Stmt(t)
	ctrls := []*controls.Control{findEmbedded(t, "builder-id-trusted")}

	opts := &VerificationOptions{
		Params: map[string]any{
			"trusted_builders": []string{"https://example.com/builder", "https://other.example.com/builder"},
		},
	}
	results, err := impl.RunControls(context.Background(), opts, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusPass, results[0].Status)
	assert.Equal(t, 2, results[0].SLSALevel)
}

func TestBuilderTrustedFailsForUntrustedBuilder(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	stmt := fullV1Stmt(t)
	ctrls := []*controls.Control{findEmbedded(t, "builder-id-trusted")}

	opts := &VerificationOptions{
		Params: map[string]any{
			"trusted_builders": []string{"https://other.example.com/builder"},
		},
	}
	results, err := impl.RunControls(context.Background(), opts, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusFail, results[0].Status)
}

// An allowlist entry without a ref trusts the builder at any ref; one
// with a ref trusts exactly that ref; a shared prefix is not a match.
func TestBuilderTrustedMatchesRefs(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	const generator = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml"
	ctrls := []*controls.Control{findEmbedded(t, "builder-id-trusted")}
	for _, tc := range []struct {
		name    string
		fixture string
		trusted []string
		want    Status
	}{
		{name: "bare entry matches the builder at a tag", fixture: "gha-generic-v02-tag.intoto.json", trusted: []string{generator}, want: StatusPass},
		{name: "entry at the same tag", fixture: "gha-generic-v02-tag.intoto.json", trusted: []string{generator + "@refs/tags/v1.2.2"}, want: StatusPass},
		{name: "entry at another tag", fixture: "gha-generic-v02-tag.intoto.json", trusted: []string{generator + "@refs/tags/v1.2.3"}, want: StatusFail},
		{name: "prefix is not a match", fixture: "gha-generic-v02-tag.intoto.json", trusted: []string{"https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic"}, want: StatusFail},
		{name: "bare entry matches the builder at a commit", fixture: "tejolote-v1-tag.intoto.json", trusted: []string{"https://github.com/carabiner-dev/bnd/.github/workflows/release.yaml"}, want: StatusPass},
		{name: "another workflow in the repository", fixture: "tejolote-v1-tag.intoto.json", trusted: []string{"https://github.com/carabiner-dev/bnd/.github/workflows/tests.yaml"}, want: StatusFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stmt := loadPlainFixture(t, tc.fixture)
			opts := &VerificationOptions{Params: map[string]any{"trusted_builders": tc.trusted}}
			results, err := impl.RunControls(context.Background(), opts, ctrls, stmt)
			require.NoError(t, err)
			require.Len(t, results, 1)
			assert.Equal(t, tc.want, results[0].Status, results[0].Message)
		})
	}
}

func TestBuilderTrustedMissingParamErrors(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	stmt := fullV1Stmt(t)
	ctrls := []*controls.Control{findEmbedded(t, "builder-id-trusted")}

	results, err := impl.RunControls(context.Background(), &VerificationOptions{Params: map[string]any{}}, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusError, results[0].Status)
	assert.Contains(t, results[0].Message, "trusted_builders")
}

func TestProvenanceL2CompleteHappyPath(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	stmt := fullV1Stmt(t)
	ctrls := []*controls.Control{findEmbedded(t, "provenance-l2-complete")}

	results, err := impl.RunControls(context.Background(), &VerificationOptions{}, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusPass, results[0].Status)
}

func TestProvenanceL2CompleteFailsWhenBuilderMissing(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	stmt := fullV1Stmt(t)
	pred, ok := stmt.pred.GetParsed().(*provenancev1.Provenance)
	require.True(t, ok)
	pred.RunDetails.Builder.Id = ""

	ctrls := []*controls.Control{findEmbedded(t, "provenance-l2-complete")}
	results, err := impl.RunControls(context.Background(), &VerificationOptions{}, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusFail, results[0].Status)
}

func TestInvocationIdControl(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	stmt := fullV1Stmt(t)
	ctrls := []*controls.Control{findEmbedded(t, "provenance-has-invocation-id")}

	// Happy path.
	results, err := impl.RunControls(context.Background(), &VerificationOptions{}, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusPass, results[0].Status)
	assert.Equal(t, 3, results[0].SLSALevel)

	// Stripped invocation ID — should fail.
	pred, ok := stmt.pred.GetParsed().(*provenancev1.Provenance)
	require.True(t, ok)
	pred.RunDetails.Metadata.InvocationId = ""
	results, err = impl.RunControls(context.Background(), &VerificationOptions{}, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusFail, results[0].Status)
}

func TestResolvedDependenciesControl(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	stmt := fullV1Stmt(t)
	ctrls := []*controls.Control{findEmbedded(t, "provenance-has-resolved-dependencies")}

	// Happy path.
	results, err := impl.RunControls(context.Background(), &VerificationOptions{}, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusPass, results[0].Status)
	assert.Equal(t, 3, results[0].SLSALevel)

	// Empty resolved dependencies — should fail.
	pred, ok := stmt.pred.GetParsed().(*provenancev1.Provenance)
	require.True(t, ok)
	pred.BuildDefinition.ResolvedDependencies = nil
	results, err = impl.RunControls(context.Background(), &VerificationOptions{}, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusFail, results[0].Status)
}

// TestSLSALevelClimbsWhenAllLevelsPass exercises ComputeResult with the
// new L2/L3 controls so we can confirm the level computation reaches 3
// when every level's controls pass.
func TestSLSALevelClimbsWhenAllLevelsPass(t *testing.T) {
	t.Parallel()

	impl := &defaultImplementation{}
	r, err := impl.ComputeResult(
		nil,
		[]*ControlResult{
			{ID: "source-repo-match", SLSALevel: 1, Status: StatusPass},
			{ID: "builder-id-trusted", SLSALevel: 2, Status: StatusPass},
			{ID: "provenance-l2-complete", SLSALevel: 2, Status: StatusPass},
			{ID: "provenance-has-invocation-id", SLSALevel: 3, Status: StatusPass},
			{ID: "provenance-has-resolved-dependencies", SLSALevel: 3, Status: StatusPass},
		},
		nil, nil,
	)
	require.NoError(t, err)
	assert.Equal(t, StatusPass, r.Status)
	assert.Equal(t, 3, r.SLSALevel)
}
