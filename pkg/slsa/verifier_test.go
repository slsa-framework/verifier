// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package slsa_test

import (
	"context"
	"errors"
	"testing"

	"github.com/policylabs/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/verifier/pkg/slsa"
	"github.com/slsa-framework/verifier/pkg/slsa/controls"
	"github.com/slsa-framework/verifier/pkg/slsa/slsafakes"
)

// fakeStatement is the minimal attestation.Statement implementation used in
// tests where the statement contents are irrelevant.
type fakeStatement struct{}

func (*fakeStatement) GetSubjects() []attestation.Subject          { return nil }
func (*fakeStatement) GetPredicate() attestation.Predicate         { return nil }
func (*fakeStatement) GetPredicateType() attestation.PredicateType { return "" }
func (*fakeStatement) GetType() string                             { return "" }
func (*fakeStatement) GetVerification() attestation.Verification   { return nil }

func newPassingFake() *slsafakes.FakeVerifierImplementation {
	f := &slsafakes.FakeVerifierImplementation{}
	f.ResolveCategoryReturns(controls.BuildCore, nil)
	f.ComputeResultReturns(&slsa.Result{Status: slsa.StatusPass}, nil)
	return f
}

func TestNewLoadsEmbeddedCatalog(t *testing.T) {
	t.Parallel()

	v, err := slsa.New()
	require.NoError(t, err)
	require.NotNil(t, v)
	require.NotNil(t, v.Options.Catalog)
	assert.NotEmpty(t, v.Options.Catalog.Get(controls.BuildCore))
}

func TestNewWithCatalogOverride(t *testing.T) {
	t.Parallel()

	custom := &controls.Catalog{Controls: map[controls.Category][]*controls.Control{}}
	v, err := slsa.New(slsa.WithCatalog(custom))
	require.NoError(t, err)
	assert.Same(t, custom, v.Options.Catalog)
}

func TestNewOptionErrorPropagates(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("boom")
	failOpt := func(*slsa.Verifier) error { return wantErr }
	_, err := slsa.New(failOpt)
	require.ErrorIs(t, err, wantErr)
}

func TestVerifyRequiresStatement(t *testing.T) {
	t.Parallel()

	v, err := slsa.New(slsa.WithImplementation(newPassingFake()))
	require.NoError(t, err)

	_, err = v.Verify(context.Background(), nil)
	assert.Error(t, err)
}

func TestVerifyCallsLayersInOrder(t *testing.T) {
	t.Parallel()

	fake := newPassingFake()
	v, err := slsa.New(slsa.WithImplementation(fake))
	require.NoError(t, err)

	res, err := v.Verify(context.Background(), &fakeStatement{})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, slsa.StatusPass, res.Status)

	assert.Equal(t, 1, fake.VerifySignaturesCallCount())
	assert.Equal(t, 1, fake.CheckIdentitiesCallCount())
	assert.Equal(t, 1, fake.CheckSubjectsCallCount())
	assert.Equal(t, 1, fake.ResolveCategoryCallCount())
	// SelectCoreControls + SelectBuildTypeControls + SelectUserControls each once
	assert.Equal(t, 1, fake.SelectCoreControlsCallCount())
	assert.Equal(t, 1, fake.SelectBuildTypeControlsCallCount())
	assert.Equal(t, 1, fake.SelectUserControlsCallCount())
	// RunControls is called three times (core, buildType, user)
	assert.Equal(t, 3, fake.RunControlsCallCount())
	assert.Equal(t, 1, fake.ComputeResultCallCount())
}

func TestVerifyShortCircuitsOnSignatureFailure(t *testing.T) {
	t.Parallel()

	fake := newPassingFake()
	wantErr := errors.New("bad signature")
	fake.VerifySignaturesReturns(wantErr)

	v, err := slsa.New(slsa.WithImplementation(fake))
	require.NoError(t, err)

	_, err = v.Verify(context.Background(), &fakeStatement{})
	require.ErrorIs(t, err, wantErr)

	// No subsequent layers should have been invoked.
	assert.Zero(t, fake.CheckIdentitiesCallCount())
	assert.Zero(t, fake.ResolveCategoryCallCount())
	assert.Zero(t, fake.RunControlsCallCount())
}

func TestVerifyDisableBuildTypeControls(t *testing.T) {
	t.Parallel()

	fake := newPassingFake()
	v, err := slsa.New(slsa.WithImplementation(fake))
	require.NoError(t, err)

	_, err = v.Verify(context.Background(), &fakeStatement{}, slsa.WithBuildTypeControls(false))
	require.NoError(t, err)

	assert.Zero(t, fake.SelectBuildTypeControlsCallCount())
	// Core + user runs only — buildType skipped.
	assert.Equal(t, 2, fake.RunControlsCallCount())
}

func TestVerifyDisableUserControls(t *testing.T) {
	t.Parallel()

	fake := newPassingFake()
	v, err := slsa.New(slsa.WithImplementation(fake))
	require.NoError(t, err)

	_, err = v.Verify(context.Background(), &fakeStatement{}, slsa.WithUserControls(false))
	require.NoError(t, err)

	assert.Zero(t, fake.SelectUserControlsCallCount())
	// Core + buildType runs only — user skipped.
	assert.Equal(t, 2, fake.RunControlsCallCount())
}

func TestVerifyParamsForwarded(t *testing.T) {
	t.Parallel()

	fake := newPassingFake()
	v, err := slsa.New(slsa.WithImplementation(fake))
	require.NoError(t, err)

	_, err = v.Verify(
		context.Background(),
		&fakeStatement{},
		slsa.WithParam("expected_source", "git+https://example.com/repo"),
		slsa.WithParam("names", []string{"alice", "bob"}),
	)
	require.NoError(t, err)

	_, gotOpts, _ := fake.VerifySignaturesArgsForCall(0)
	require.NotNil(t, gotOpts)
	assert.Equal(t, "git+https://example.com/repo", gotOpts.Params["expected_source"])
	assert.Equal(t, []string{"alice", "bob"}, gotOpts.Params["names"])
}

func TestDefaultVerificationOptionsApplied(t *testing.T) {
	t.Parallel()

	custom := &slsa.VerificationOptions{
		RunBuildTypeControls: false,
		RunUserControls:      false,
		Params:               map[string]any{"k": "v"},
	}
	fake := newPassingFake()
	v, err := slsa.New(
		slsa.WithImplementation(fake),
		slsa.WithDefaultVerificationOptions(custom),
	)
	require.NoError(t, err)

	_, err = v.Verify(context.Background(), &fakeStatement{})
	require.NoError(t, err)

	_, gotOpts, _ := fake.VerifySignaturesArgsForCall(0)
	assert.False(t, gotOpts.RunBuildTypeControls)
	assert.False(t, gotOpts.RunUserControls)
	assert.Equal(t, "v", gotOpts.Params["k"])
	// Both buildType and user control runs should be skipped.
	assert.Equal(t, 1, fake.RunControlsCallCount())
}
