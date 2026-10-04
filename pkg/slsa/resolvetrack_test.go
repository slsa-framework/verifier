// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
	"testing"

	"github.com/policylabs/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/verifier/pkg/slsa/controls"
	"github.com/slsa-framework/verifier/pkg/slsa/eval"
)

// multiTrackCatalog returns a synthetic Catalog where the v1 build
// provenance predicate type is associated with both the build and
// source tracks — the scenario the user wants to support via
// VerificationOptions.ForceTrack.
func multiTrackCatalog() *controls.Catalog {
	pt := eval.PredicateProvenanceV1
	build := &controls.Control{
		ID: "build-side", Title: "Build", Track: string(controls.TrackBuild),
		Checks: []controls.Check{{PredicateType: pt, Expression: "true"}},
	}
	source := &controls.Control{
		ID: "source-side", Title: "Source", Track: string(controls.TrackSource),
		Checks: []controls.Check{{PredicateType: pt, Expression: "true"}},
	}
	return &controls.Catalog{
		Controls: map[controls.Category][]*controls.Control{
			"build/core":  {build},
			"source/core": {source},
		},
		PredicateTracks: controls.BuildPredicateTracks([]*controls.Control{build, source}),
	}
}

func v1Stmt() *fakeStmt {
	return &fakeStmt{pType: attestation.PredicateType(eval.PredicateProvenanceV1)}
}

func TestResolveTrackUnknownPredicate(t *testing.T) {
	t.Parallel()

	cat, err := controls.LoadEmbedded()
	require.NoError(t, err)
	stmt := &fakeStmt{pType: "https://example.com/unknown"}

	_, rtErr := resolveTrack(&VerificationOptions{}, cat, stmt)
	require.Error(t, rtErr)
	assert.Contains(t, rtErr.Error(), "no controls registered")
}

func TestResolveTrackSingleTrackAuto(t *testing.T) {
	t.Parallel()

	cat, err := controls.LoadEmbedded()
	require.NoError(t, err)

	got, rtErr := resolveTrack(&VerificationOptions{}, cat, v1Stmt())
	require.NoError(t, rtErr)
	assert.Equal(t, controls.TrackBuild, got)
}

func TestResolveTrackSingleTrackForceMatching(t *testing.T) {
	t.Parallel()

	cat, err := controls.LoadEmbedded()
	require.NoError(t, err)

	got, rtErr := resolveTrack(
		&VerificationOptions{ForceTrack: controls.TrackBuild}, cat, v1Stmt(),
	)
	require.NoError(t, rtErr)
	assert.Equal(t, controls.TrackBuild, got)
}

func TestResolveTrackSingleTrackForceWrongErrors(t *testing.T) {
	t.Parallel()

	cat, err := controls.LoadEmbedded()
	require.NoError(t, err)

	_, rtErr := resolveTrack(
		&VerificationOptions{ForceTrack: controls.TrackSource}, cat, v1Stmt(),
	)
	require.Error(t, rtErr)
	assert.Contains(t, rtErr.Error(), "not applicable to forced track")
}

func TestResolveTrackMultiTrackAutoErrors(t *testing.T) {
	t.Parallel()

	cat := multiTrackCatalog()

	_, rtErr := resolveTrack(&VerificationOptions{}, cat, v1Stmt())
	require.Error(t, rtErr)
	assert.Contains(t, rtErr.Error(), "set --track to disambiguate")
}

func TestResolveTrackMultiTrackForceBuild(t *testing.T) {
	t.Parallel()

	cat := multiTrackCatalog()

	got, rtErr := resolveTrack(
		&VerificationOptions{ForceTrack: controls.TrackBuild}, cat, v1Stmt(),
	)
	require.NoError(t, rtErr)
	assert.Equal(t, controls.TrackBuild, got)
}

func TestResolveTrackMultiTrackForceSource(t *testing.T) {
	t.Parallel()

	cat := multiTrackCatalog()

	got, rtErr := resolveTrack(
		&VerificationOptions{ForceTrack: controls.TrackSource}, cat, v1Stmt(),
	)
	require.NoError(t, rtErr)
	assert.Equal(t, controls.TrackSource, got)
}
