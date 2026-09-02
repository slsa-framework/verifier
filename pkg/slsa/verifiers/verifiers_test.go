// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package verifiers_test

import (
	"os"
	"path/filepath"
	"testing"

	sapi "github.com/carabiner-dev/signer/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/verifier/pkg/slsa/builders"
	"github.com/slsa-framework/verifier/pkg/slsa/verifiers"
)

const (
	githubIssuer    = "https://token.actions.githubusercontent.com"
	sourceActions   = "https://github.com/slsa-framework/source-actions"
	sourceWorkflow  = sourceActions + "/.github/workflows/compute_slsa_source.yml"
	slsaActions     = "https://github.com/slsa-framework/actions"
	currentWorkflow = slsaActions + "/.github/workflows/compute_slsa_source.yml"
	sourcePoc       = "https://github.com/slsa-framework/slsa-source-poc"
	pocWorkflow     = sourcePoc + "/.github/workflows/compute_slsa_source.yml"
)

func githubSigner(subject string) *sapi.Identity {
	return &sapi.Identity{Sigstore: &sapi.IdentitySigstore{Issuer: githubIssuer, Identity: subject}}
}

func TestVerifierValidate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		verifier verifiers.Verifier
		wantErr  string
	}{
		{name: "issuer derived", verifier: verifiers.Verifier{ID: sourceActions, Issuer: githubIssuer}},
		{name: "explicit signer", verifier: verifiers.Verifier{ID: sourceActions, Signer: "sigstore::" + githubIssuer + "::" + sourceWorkflow + "@refs/heads/main"}},
		{name: "empty id", verifier: verifiers.Verifier{Issuer: githubIssuer}, wantErr: "empty id"},
		{name: "bad idMatch", verifier: verifiers.Verifier{ID: sourceActions, Issuer: githubIssuer, IDMatch: "glob"}, wantErr: "idMatch"},
		{name: "bad ref", verifier: verifiers.Verifier{ID: sourceActions, Issuer: githubIssuer, Ref: "tag"}, wantErr: "ref must be"},
		{name: "no signer nor issuer", verifier: verifiers.Verifier{ID: sourceActions}, wantErr: "set signer or issuer"},
		{name: "bad spec", verifier: verifiers.Verifier{ID: sourceActions, Signer: "sigstore(identityMatch=nope)::a::b"}, wantErr: "signer identity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := tc.verifier
			err := v.Validate()
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, v.Identity())
		})
	}
}

// A verifier bound by issuer accepts any workflow of its repository;
// one bound by an explicit signer accepts only that workflow; the ref
// policy applies to whichever signed.
func TestVerifierSigners(t *testing.T) {
	t.Parallel()
	byIssuer := &verifiers.Verifier{ID: sourceActions, Issuer: githubIssuer}
	require.NoError(t, byIssuer.Validate())
	assert.Equal(t, "sigstore(identityMatch=prefix)::"+githubIssuer+"::"+sourceActions+"/", byIssuer.SignerSpec())
	assert.True(t, byIssuer.AllowsSigner(githubSigner(sourceWorkflow+"@refs/heads/main")))
	assert.True(t, byIssuer.AllowsSigner(githubSigner(sourceActions+"/.github/workflows/other.yml@refs/heads/main")))
	assert.False(t, byIssuer.AllowsSigner(githubSigner(sourceActions+"-fork/.github/workflows/compute_slsa_source.yml@refs/heads/main")))
	assert.False(t, byIssuer.AllowsSigner(&sapi.Identity{Sigstore: &sapi.IdentitySigstore{Issuer: "https://accounts.google.com", Identity: sourceWorkflow}}))

	exact := &verifiers.Verifier{ID: sourceActions, Signer: "sigstore(identityMatch=prefix)::" + githubIssuer + "::" + sourceWorkflow + "@", Ref: builders.RefSemverTag}
	require.NoError(t, exact.Validate())
	assert.True(t, exact.MatchesSigner(githubSigner(sourceWorkflow+"@refs/heads/main")))
	assert.False(t, exact.AllowsSigner(githubSigner(sourceWorkflow+"@refs/heads/main")), "a branch is not a release tag")
	assert.True(t, exact.AllowsSigner(githubSigner(sourceWorkflow+"@refs/tags/v1.2.3")))
	assert.False(t, exact.MatchesSigner(githubSigner(sourceActions+"/.github/workflows/other.yml@refs/tags/v1.2.3")))
}

func TestEmbeddedRegistry(t *testing.T) {
	t.Parallel()
	r, err := verifiers.LoadEmbedded()
	require.NoError(t, err)
	assert.Equal(t, 3, r.Len())

	// The current workflow is pinned by its callers to a digest or a
	// tag, so any ref is its signer.
	current := r.Lookup(slsaActions)
	require.NotNil(t, current)
	for _, ref := range []string{"dea965cdca5e0cb422bf7b2653c9d15f678ad01c", "refs/tags/v0.1.0", "refs/heads/main"} {
		assert.True(t, current.AllowsSigner(githubSigner(currentWorkflow+"@"+ref)), ref)
	}
	assert.False(t, current.AllowsSigner(githubSigner(slsaActions+"/.github/workflows/release.yaml@refs/heads/main")), "another workflow of the repository")
	assert.False(t, current.AllowsSigner(githubSigner(slsaActions+"-fork/.github/workflows/compute_slsa_source.yml@refs/heads/main")), "a lookalike repository")
	assert.False(t, current.AllowsSigner(githubSigner(sourceWorkflow+"@refs/heads/main")), "the legacy workflow does not sign for the current id")
	assert.False(t, current.AllowsSigner(&sapi.Identity{Sigstore: &sapi.IdentitySigstore{Issuer: "https://accounts.google.com", Identity: currentWorkflow + "@refs/heads/main"}}))

	// The legacy workflows only ever ran from main
	for id, workflow := range map[string]string{sourceActions: sourceWorkflow, sourcePoc: pocWorkflow} {
		legacy := r.Lookup(id)
		require.NotNil(t, legacy, id)
		assert.True(t, legacy.AllowsSigner(githubSigner(workflow+"@refs/heads/main")), id)
		assert.False(t, legacy.AllowsSigner(githubSigner(workflow+"@refs/tags/v0.1.0")), id)
		assert.False(t, legacy.AllowsSigner(githubSigner(currentWorkflow+"@refs/heads/main")), id)
	}
	assert.Nil(t, r.Lookup("https://verify.example.com"))
}

func TestRegistry(t *testing.T) {
	t.Parallel()
	r, err := verifiers.New(
		&verifiers.Verifier{ID: "https://github.com/", IDMatch: builders.IDMatchPrefix, Issuer: githubIssuer, Title: "platform"},
		&verifiers.Verifier{ID: sourceActions, Issuer: githubIssuer, Title: "source-actions"},
	)
	require.NoError(t, err)
	assert.Equal(t, "source-actions", r.Lookup(sourceActions).Title)
	assert.Equal(t, "platform", r.Lookup("https://github.com/org/verifier").Title)
	assert.Nil(t, r.Lookup("https://verify.example.com"))

	override, err := verifiers.New(&verifiers.Verifier{ID: sourceActions, Issuer: githubIssuer, Title: "mine"})
	require.NoError(t, err)
	require.NoError(t, r.Merge(override))
	assert.Equal(t, 2, r.Len())
	assert.Equal(t, "mine", r.Lookup(sourceActions).Title)
	require.Error(t, r.Add(&verifiers.Verifier{ID: "broken"}))

	var empty *verifiers.Registry
	assert.Equal(t, 0, empty.Len())
	assert.Nil(t, empty.Lookup(sourceActions))
}

func TestLoad(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	one := filepath.Join(dir, "one.yaml")
	require.NoError(t, os.WriteFile(one, []byte("verifiers:\n  - id: https://verify.example.com\n    signer: spiffe://example.com/verifier\n    title: a\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "two.yml"), []byte("verifiers:\n  - id: https://verify.example.com\n    signer: spiffe://example.com/verifier\n    title: a-override\n"), 0o600))

	r, err := verifiers.Load(one)
	require.NoError(t, err)
	assert.Equal(t, "a", r.Lookup("https://verify.example.com").Title)
	r, err = verifiers.Load(dir)
	require.NoError(t, err)
	assert.Equal(t, "a-override", r.Lookup("https://verify.example.com").Title)
	_, err = verifiers.Load(filepath.Join(dir, "missing.yaml"))
	require.Error(t, err)
	_, err = verifiers.Parse([]byte("verifiers:\n  - title: no id\n"))
	require.ErrorContains(t, err, "empty id")
	_, err = verifiers.Parse([]byte("verifiers: [\n"))
	require.Error(t, err)
}
