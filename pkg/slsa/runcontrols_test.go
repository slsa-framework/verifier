// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
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

// fakePredicate is a minimal attestation.Predicate carrying a parsed
// proto message and a predicate-type URI for tests.
type fakePredicate struct {
	parsed any
	pType  attestation.PredicateType
}

func (p *fakePredicate) GetType() attestation.PredicateType { return p.pType }
func (p *fakePredicate) SetType(t attestation.PredicateType) error {
	p.pType = t
	return nil
}
func (p *fakePredicate) GetParsed() any                             { return p.parsed }
func (p *fakePredicate) GetData() []byte                            { return nil }
func (p *fakePredicate) GetVerification() attestation.Verification  { return nil }
func (p *fakePredicate) GetOrigin() attestation.Subject             { return nil }
func (p *fakePredicate) SetOrigin(_ attestation.Subject)            {}
func (p *fakePredicate) SetVerification(_ attestation.Verification) {}

// fakeStmt is a minimal attestation.Statement wrapping a fakePredicate.
type fakeStmt struct {
	pType    attestation.PredicateType
	pred     attestation.Predicate
	subjects []attestation.Subject
}

func (s *fakeStmt) GetSubjects() []attestation.Subject          { return s.subjects }
func (s *fakeStmt) GetPredicate() attestation.Predicate         { return s.pred }
func (s *fakeStmt) GetPredicateType() attestation.PredicateType { return s.pType }
func (s *fakeStmt) GetType() string                             { return "" }
func (s *fakeStmt) GetVerification() attestation.Verification   { return nil }

// fakeSubject is a minimal attestation.Subject for tests.
type fakeSubject struct {
	name   string
	uri    string
	digest map[string]string
}

func (s *fakeSubject) GetName() string              { return s.name }
func (s *fakeSubject) GetUri() string               { return s.uri }
func (s *fakeSubject) GetDigest() map[string]string { return s.digest }

func newProvV1Stmt(t *testing.T, source string) *fakeStmt {
	t.Helper()
	ext, err := structpb.NewStruct(map[string]any{"source": source})
	require.NoError(t, err)
	return &fakeStmt{
		pType: attestation.PredicateType(eval.PredicateProvenanceV1),
		pred: &fakePredicate{
			pType: attestation.PredicateType(eval.PredicateProvenanceV1),
			parsed: &provenancev1.Provenance{
				BuildDefinition: &provenancev1.BuildDefinition{
					BuildType:          "https://example.com/buildType/v1",
					ExternalParameters: ext,
				},
				RunDetails: &provenancev1.RunDetails{
					Builder: &provenancev1.Builder{Id: "https://example.com/builder"},
				},
			},
		},
	}
}

func newDefaultImpl(t *testing.T) *defaultImplementation {
	t.Helper()
	impl, err := newDefaultImplementation()
	require.NoError(t, err)
	return impl
}

func TestResolveCategoryBuild(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	cat, err := controls.LoadEmbedded()
	require.NoError(t, err)
	for _, pt := range []string{
		eval.PredicateProvenanceV01,
		eval.PredicateProvenanceV02,
		eval.PredicateProvenanceV1,
	} {
		stmt := &fakeStmt{pType: attestation.PredicateType(pt)}
		got, rcErr := impl.ResolveCategory(&VerificationOptions{}, cat, stmt)
		require.NoError(t, rcErr)
		assert.Equal(t, controls.BuildCore, got, "predicateType=%s", pt)
	}
}

func TestResolveCategorySource(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	cat, err := controls.LoadEmbedded()
	require.NoError(t, err)
	stmt := &fakeStmt{pType: attestation.PredicateType(eval.PredicateSourceProvenance)}
	got, rcErr := impl.ResolveCategory(&VerificationOptions{}, cat, stmt)
	require.NoError(t, rcErr)
	assert.Equal(t, controls.SourceCore, got)
}

func TestResolveCategoryUnknown(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	cat, err := controls.LoadEmbedded()
	require.NoError(t, err)
	stmt := &fakeStmt{pType: "https://example.com/unknown"}
	_, rcErr := impl.ResolveCategory(&VerificationOptions{}, cat, stmt)
	assert.Error(t, rcErr)
}

func TestRunControlsPass(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	stmt := newProvV1Stmt(t, "git+https://example.com/repo")

	ctrls := []*controls.Control{{
		ID:    "source-repo-match",
		Title: "Source repo match",
		Checks: []controls.Check{{
			PredicateType: eval.PredicateProvenanceV1,
			Expression:    "predicate.buildDefinition.externalParameters.source == params.expected_source",
			Parameters:    []string{"expected_source"},
		}},
	}}

	opts := &VerificationOptions{Params: map[string]any{"expected_source": "git+https://example.com/repo"}}
	results, err := impl.RunControls(context.Background(), opts, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusPass, results[0].Status)
	assert.Equal(t, "source-repo-match", results[0].ID)
}

func TestRunControlsFail(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	stmt := newProvV1Stmt(t, "git+https://example.com/wrong")

	ctrls := []*controls.Control{{
		ID:    "source-repo-match",
		Title: "Source repo match",
		Checks: []controls.Check{{
			PredicateType: eval.PredicateProvenanceV1,
			Expression:    "predicate.buildDefinition.externalParameters.source == params.expected_source",
			Parameters:    []string{"expected_source"},
		}},
	}}

	opts := &VerificationOptions{Params: map[string]any{"expected_source": "git+https://example.com/repo"}}
	results, err := impl.RunControls(context.Background(), opts, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusFail, results[0].Status)
}

func TestRunControlsMissingParam(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	stmt := newProvV1Stmt(t, "x")

	ctrls := []*controls.Control{{
		ID:    "source-repo-match",
		Title: "Source repo match",
		Checks: []controls.Check{{
			PredicateType: eval.PredicateProvenanceV1,
			Expression:    "predicate.buildDefinition.externalParameters.source == params.expected_source",
			Parameters:    []string{"expected_source"},
		}},
	}}

	opts := &VerificationOptions{Params: map[string]any{}}
	results, err := impl.RunControls(context.Background(), opts, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusError, results[0].Status)
	assert.Contains(t, results[0].Message, "expected_source")
}

func TestRunControlsMissingOptionalParamSkips(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	stmt := newProvV1Stmt(t, "git+https://example.com/repo")

	ctrls := []*controls.Control{{
		ID:    "source-repo-match",
		Title: "Source repo match",
		Checks: []controls.Check{{
			PredicateType:      eval.PredicateProvenanceV1,
			Expression:         "predicate.buildDefinition.externalParameters.source == params.expected_source",
			OptionalParameters: []string{"expected_source"},
		}},
	}}

	// Without the param the check is skipped, not errored.
	opts := &VerificationOptions{Params: map[string]any{}}
	results, err := impl.RunControls(context.Background(), opts, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusSkipped, results[0].Status)
	assert.Contains(t, results[0].Message, "expected_source")

	// With the param provided the check evaluates normally.
	opts = &VerificationOptions{Params: map[string]any{"expected_source": "git+https://example.com/repo"}}
	results, err = impl.RunControls(context.Background(), opts, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusPass, results[0].Status)
}

func TestRunControlsSkipsControlWithoutMatchingPredicate(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	stmt := newProvV1Stmt(t, "x")

	ctrls := []*controls.Control{{
		ID:    "applies-to-v02",
		Title: "v0.2 only",
		Checks: []controls.Check{{
			PredicateType: eval.PredicateProvenanceV02,
			Expression:    "true",
		}},
	}}

	opts := &VerificationOptions{Params: map[string]any{}}
	results, err := impl.RunControls(context.Background(), opts, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusSkipped, results[0].Status)
}

func TestRunControlsExposesSubjects(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	stmt := newProvV1Stmt(t, "x")
	stmt.subjects = []attestation.Subject{
		&fakeSubject{name: "main", digest: map[string]string{"sha256": "abc"}},
	}

	ctrls := []*controls.Control{{
		ID:    "subject-name",
		Title: "Subject name",
		Checks: []controls.Check{{
			PredicateType: eval.PredicateProvenanceV1,
			Expression:    `subjects.size() == 1 && subjects[0].name == "main"`,
		}},
	}}

	opts := &VerificationOptions{Params: map[string]any{}}
	results, err := impl.RunControls(context.Background(), opts, ctrls, stmt)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, StatusPass, results[0].Status)
}

func TestRunControlsErrorsWhenPredicateMissing(t *testing.T) {
	t.Parallel()

	impl := newDefaultImpl(t)
	// Statement with no predicate.
	stmt := &fakeStmt{pType: attestation.PredicateType(eval.PredicateProvenanceV1)}

	ctrls := []*controls.Control{{
		ID:    "x",
		Title: "X",
		Checks: []controls.Check{{
			PredicateType: eval.PredicateProvenanceV1,
			Expression:    "true",
		}},
	}}

	opts := &VerificationOptions{}
	_, err := impl.RunControls(context.Background(), opts, ctrls, stmt)
	require.Error(t, err)
}

func TestConvertSubjects(t *testing.T) {
	t.Parallel()

	subs := []attestation.Subject{
		&fakeSubject{name: "a", digest: map[string]string{"sha256": "1"}},
		&fakeSubject{uri: "pkg:foo", digest: map[string]string{"sha256": "2"}},
	}
	got := convertSubjects(subs)
	require.Len(t, got, 2)
	assert.Equal(t, "a", got[0].GetName())
	assert.Equal(t, "1", got[0].GetDigest()["sha256"])
	assert.Equal(t, "pkg:foo", got[1].GetUri())
}
