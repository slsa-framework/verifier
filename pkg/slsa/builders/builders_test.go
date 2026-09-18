// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package builders_test

import (
	"os"
	"path/filepath"
	"testing"

	sapi "github.com/carabiner-dev/signer/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/verifier/pkg/slsa/builders"
)

const (
	githubIssuer = "https://token.actions.githubusercontent.com"
	generatorID  = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml"
	delegatorID  = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/delegator_generic_slsa3.yml"
)

func githubSigner(subject string) *sapi.Identity {
	return &sapi.Identity{Sigstore: &sapi.IdentitySigstore{Issuer: githubIssuer, Identity: subject}}
}

func TestRefPolicyAllows(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		policy builders.RefPolicy
		ref    string
		want   bool
	}{
		{policy: builders.RefAny, ref: "refs/heads/main", want: true},
		{policy: builders.RefAny, ref: "", want: true},
		{policy: "", ref: "refs/heads/main", want: true},
		{policy: builders.RefSemverTag, ref: "refs/tags/v1.2.3", want: true},
		{policy: builders.RefSemverTag, ref: "refs/tags/v1.2.3-rc.1", want: true},
		{policy: builders.RefSemverTag, ref: "refs/tags/v1.2", want: false},
		{policy: builders.RefSemverTag, ref: "refs/tags/v1", want: false},
		{policy: builders.RefSemverTag, ref: "refs/tags/v1.2.3+build", want: false},
		{policy: builders.RefSemverTag, ref: "refs/tags/1.2.3", want: false},
		{policy: builders.RefSemverTag, ref: "refs/heads/main", want: false},
		{policy: builders.RefSemverTag, ref: "v1.2.3", want: false},
		{policy: builders.RefSemverTag, ref: "", want: false},
		{policy: "whatever", ref: "refs/tags/v1.2.3", want: false},
	} {
		t.Run(string(tc.policy)+" "+tc.ref, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tc.policy.Allows(tc.ref))
		})
	}
}

func TestBuilderValidate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		builder builders.Builder
		wantErr string
	}{
		{name: "issuer derived", builder: builders.Builder{ID: generatorID, Issuer: githubIssuer}},
		{name: "explicit signer", builder: builders.Builder{ID: generatorID, Signer: "sigstore::" + githubIssuer + "::" + generatorID + "@refs/tags/v2.0.0"}},
		{name: "empty id", builder: builders.Builder{Issuer: githubIssuer}, wantErr: "empty id"},
		{name: "id with ref", builder: builders.Builder{ID: generatorID + "@refs/tags/v1", Issuer: githubIssuer}, wantErr: "must not carry a ref"},
		{name: "bad idMatch", builder: builders.Builder{ID: generatorID, Issuer: githubIssuer, IDMatch: "glob"}, wantErr: "idMatch"},
		{name: "bad ref policy", builder: builders.Builder{ID: generatorID, Issuer: githubIssuer, Ref: "tag"}, wantErr: "ref must be"},
		{name: "no signer nor issuer", builder: builders.Builder{ID: generatorID}, wantErr: "set signer or issuer"},
		{name: "bad signer spec", builder: builders.Builder{ID: generatorID, Signer: "sigstore(identityMatch=nope)::a::b"}, wantErr: "signer identity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := tc.builder
			err := b.Validate()
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				assert.Nil(t, b.Identity())
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, b.Identity())
		})
	}
}

func TestSignerSpec(t *testing.T) {
	t.Parallel()
	exact := builders.Builder{ID: generatorID, Issuer: githubIssuer}
	assert.Equal(t, "sigstore(identityMatch=prefix)::"+githubIssuer+"::"+generatorID+"@", exact.SignerSpec())
	prefix := builders.Builder{ID: "https://github.com/", IDMatch: builders.IDMatchPrefix, Issuer: githubIssuer}
	assert.Equal(t, "sigstore(identityMatch=prefix)::"+githubIssuer+"::https://github.com/", prefix.SignerSpec())
	explicit := builders.Builder{ID: generatorID, Issuer: githubIssuer, Signer: "spiffe://example.org/builder"}
	assert.Equal(t, "spiffe://example.org/builder", explicit.SignerSpec())
}

// The derived signer identity matches the builder at any ref, not a
// builder whose id merely shares a prefix, and not another issuer.
func TestBuilderMatchesSigner(t *testing.T) {
	t.Parallel()
	b := &builders.Builder{ID: generatorID, Issuer: githubIssuer}
	require.NoError(t, b.Validate())
	assert.True(t, b.MatchesSigner(githubSigner(generatorID+"@refs/tags/v1.2.2")))
	assert.True(t, b.MatchesSigner(githubSigner(generatorID+"@refs/heads/main")))
	assert.False(t, b.MatchesSigner(githubSigner(generatorID+"-fork@refs/tags/v1.2.2")))
	assert.False(t, b.MatchesSigner(githubSigner(delegatorID+"@refs/tags/v1.2.2")))
	assert.False(t, b.MatchesSigner(&sapi.Identity{Sigstore: &sapi.IdentitySigstore{Issuer: "https://accounts.google.com", Identity: generatorID + "@refs/tags/v1.2.2"}}))
	assert.False(t, b.MatchesSigner(&sapi.Identity{Key: &sapi.IdentityKey{Id: "abc"}}))
	assert.False(t, b.MatchesSigner(nil))
	assert.False(t, (&builders.Builder{ID: generatorID, Issuer: githubIssuer}).MatchesSigner(githubSigner(generatorID+"@refs/tags/v1")), "unvalidated builder matches nothing")
}

func TestBuilderMatchesID(t *testing.T) {
	t.Parallel()
	exact := &builders.Builder{ID: generatorID}
	assert.True(t, exact.MatchesID(generatorID))
	assert.True(t, exact.MatchesID(generatorID+"@refs/tags/v1.2.2"))
	assert.False(t, exact.MatchesID(generatorID+"-fork"))
	prefix := &builders.Builder{ID: "https://github.com/", IDMatch: builders.IDMatchPrefix}
	assert.True(t, prefix.MatchesID("https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main"))
	assert.False(t, prefix.MatchesID("https://gitlab.com/org/repo"))
}

func TestSplitRef(t *testing.T) {
	t.Parallel()
	base, ref := builders.SplitRef(generatorID + "@refs/tags/v1.2.2")
	assert.Equal(t, generatorID, base)
	assert.Equal(t, "refs/tags/v1.2.2", ref)
	base, ref = builders.SplitRef(generatorID)
	assert.Equal(t, generatorID, base)
	assert.Empty(t, ref)
}

// Exact entries win over prefix entries regardless of insertion order,
// and a later entry with the same id replaces the earlier one.
func TestRegistryPrecedenceAndOverride(t *testing.T) {
	t.Parallel()
	r, err := builders.New(
		&builders.Builder{ID: "https://github.com/", IDMatch: builders.IDMatchPrefix, Issuer: githubIssuer, Title: "platform"},
		&builders.Builder{ID: generatorID, Issuer: githubIssuer, Title: "generator"},
	)
	require.NoError(t, err)
	assert.Equal(t, 2, r.Len())
	assert.Equal(t, "generator", r.Lookup(generatorID+"@refs/tags/v1.2.2").Title)
	assert.Equal(t, "platform", r.Lookup("https://github.com/org/repo/.github/workflows/build.yml").Title)
	assert.Nil(t, r.Lookup("https://gitlab.com/org/repo"))
	assert.Equal(t, "generator", r.ForSigner(githubSigner(generatorID+"@refs/tags/v1.2.2")).Title)
	assert.Equal(t, "platform", r.ForSigner(githubSigner("https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main")).Title)
	assert.Nil(t, r.ForSigner(githubSigner("https://gitlab.com/org/repo")))

	override, err := builders.New(&builders.Builder{ID: generatorID, Issuer: githubIssuer, Title: "mine", Ref: builders.RefSemverTag})
	require.NoError(t, err)
	require.NoError(t, r.Merge(override))
	assert.Equal(t, 2, r.Len())
	assert.Equal(t, "mine", r.Lookup(generatorID).Title)
	assert.Equal(t, builders.RefSemverTag, r.Lookup(generatorID).Ref)

	require.Error(t, r.Add(&builders.Builder{ID: "broken"}))
	require.NoError(t, r.Merge(nil))

	var empty *builders.Registry
	assert.Equal(t, 0, empty.Len())
	assert.Nil(t, empty.Lookup(generatorID))
	assert.Nil(t, empty.ForSigner(githubSigner(generatorID)))
}

// The embedded registry knows the slsa-github-generator builders at a
// release tag, tells the delegators apart, and falls back to the
// GitHub Actions platform entry for any other workflow.
func TestEmbeddedRegistry(t *testing.T) {
	t.Parallel()
	r, err := builders.LoadEmbedded()
	require.NoError(t, err)
	assert.Equal(t, 7, r.Len())

	generator := r.ForSigner(githubSigner(generatorID + "@refs/tags/v1.2.2"))
	require.NotNil(t, generator)
	assert.Equal(t, generatorID, generator.ID)
	assert.False(t, generator.Delegated)
	assert.True(t, generator.SourceRepositoryBound)
	assert.Equal(t, builders.RefSemverTag, generator.Ref)

	delegator := r.ForSigner(githubSigner(delegatorID + "@refs/tags/v2.1.0"))
	require.NotNil(t, delegator)
	assert.True(t, delegator.Delegated)
	assert.Same(t, delegator, r.Lookup(delegatorID+"@refs/tags/v2.1.0"))

	// The attester is an observer, found by its signer identity even at a
	// branch ref; builder.id never names it, so Lookup finds the platform
	// entry instead.
	attesterID := "https://github.com/slsa-framework/actions/.github/workflows/attest_actions.yml"
	attester := r.ForSigner(githubSigner(attesterID + "@refs/heads/main"))
	require.NotNil(t, attester)
	assert.Equal(t, attesterID, attester.ID)
	assert.True(t, attester.Observer)
	assert.True(t, attester.SourceRepositoryBound)
	assert.NotEqual(t, attester, r.Lookup("https://github.com/some/repo/.github/workflows/build.yml@refs/heads/main"))

	// A BYOB custom builder and a GitHub artifact attestation workflow are
	// both plain GitHub workflows to the registry.
	for _, id := range []string{
		"https://github.com/slsa-framework/example-trw/.github/workflows/builder_high-perms_slsa3.yml@refs/tags/v1.10.0",
		"https://github.com/bazel-contrib/publish-to-bcr/.github/workflows/publish.yaml@refs/tags/v0.0.1",
	} {
		platform := r.Lookup(id)
		require.NotNil(t, platform, id)
		assert.Equal(t, builders.IDMatchPrefix, platform.IDMatch)
		assert.Same(t, platform, r.ForSigner(githubSigner(id)))
	}
	assert.Nil(t, r.Lookup("https://gitlab.com/org/repo"))
	assert.Nil(t, r.ForSigner(&sapi.Identity{Sigstore: &sapi.IdentitySigstore{Issuer: "https://accounts.google.com", Identity: generatorID + "@refs/tags/v1.2.2"}}))
}

func TestParseBinding(t *testing.T) {
	t.Parallel()
	b, err := builders.ParseBinding("https://example.com/builder=spiffe://example.org/builder")
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/builder", b.ID)
	assert.Equal(t, "spiffe://example.org/builder", b.SignerSpec())
	assert.True(t, b.MatchesSigner(&sapi.Identity{Spiffe: &sapi.IdentitySpiffe{Svid: "spiffe://example.org/builder"}}))

	b, err = builders.ParseBinding("https://gitlab.com/org/repo//.gitlab-ci.yml = https://gitlab.com")
	require.NoError(t, err)
	assert.Equal(t, "https://gitlab.com/org/repo//.gitlab-ci.yml", b.ID)
	assert.Equal(t, "https://gitlab.com", b.Issuer)
	assert.True(t, b.MatchesSigner(&sapi.Identity{Sigstore: &sapi.IdentitySigstore{Issuer: "https://gitlab.com", Identity: b.ID + "@refs/heads/main"}}))
	assert.False(t, b.SourceRepositoryBound)

	for _, s := range []string{"", "id", "=spec", "id=", "id@refs/tags/v1=https://gitlab.com"} {
		_, err := builders.ParseBinding(s)
		require.Error(t, err, s)
	}
}

func TestLoadFileAndDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	one := filepath.Join(dir, "one.yaml")
	require.NoError(t, os.WriteFile(one, []byte("builders:\n  - id: https://example.com/a\n    issuer: https://issuer.example.com\n    title: a\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "two.yml"), []byte("builders:\n  - id: https://example.com/a\n    issuer: https://issuer.example.com\n    title: a-override\n  - id: https://example.com/b\n    signer: spiffe://example.org/b\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignored"), 0o600))

	r, err := builders.Load(one)
	require.NoError(t, err)
	assert.Equal(t, 1, r.Len())
	assert.Equal(t, "a", r.Lookup("https://example.com/a").Title)

	r, err = builders.Load(dir)
	require.NoError(t, err)
	assert.Equal(t, 2, r.Len())
	assert.Equal(t, "a-override", r.Lookup("https://example.com/a").Title, "later files override earlier ones")
	assert.NotNil(t, r.Lookup("https://example.com/b"))

	_, err = builders.Load(filepath.Join(dir, "missing.yaml"))
	require.Error(t, err)

	bad := filepath.Join(dir, "bad", "bad.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(bad), 0o750))
	require.NoError(t, os.WriteFile(bad, []byte("builders:\n  - title: no id\n"), 0o600))
	_, err = builders.Load(bad)
	require.ErrorContains(t, err, "empty id")
	_, err = builders.Parse([]byte("builders: [\n"))
	require.Error(t, err)
}
