// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package slsa_test

import (
	"context"
	"testing"

	"github.com/carabiner-dev/attestation"
	sapi "github.com/carabiner-dev/signer/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/verifier/pkg/slsa"
	"github.com/slsa-framework/verifier/pkg/slsa/builders"
)

const (
	githubIssuer     = "https://token.actions.githubusercontent.com"
	generatorSubject = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v1.2.2"
	goBuilderMain    = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/heads/main"
	delegatorSubject = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/delegator_generic_slsa3.yml@refs/tags/v2.0.0"
	trwSubject       = "https://github.com/slsa-framework/example-trw/.github/workflows/builder_high-perms_slsa3.yml@refs/tags/v1.10.0"
	bcrSubject       = "https://github.com/bazel-contrib/publish-to-bcr/.github/workflows/publish.yaml@refs/tags/v0.0.1"
	bndRelease       = "https://github.com/carabiner-dev/bnd/.github/workflows/release.yaml@refs/tags/v0.4.4"
	attesterSubject  = "https://github.com/slsa-framework/actions/.github/workflows/attest_actions.yml@refs/heads/main"
	attesterObserved = "https://github.com/slsa-framework/attester/.github/workflows/release.yaml@refs/tags/v0.1.0-rc.3"
)

// signedAs wraps a fixture statement with a synthetic verification record.
type signedAs struct {
	attestation.Statement
	verification *sapi.Verification
}

func (s *signedAs) GetVerification() attestation.Verification { return s.verification }

func verifiedBy(ids ...*sapi.Identity) *sapi.Verification {
	return &sapi.Verification{Signature: &sapi.SignatureVerification{
		Verified: true, Status: sapi.VerificationStatus_VERIFIED, Identities: ids,
	}}
}

func githubIdentity(subject, sourceRepo string) *sapi.Identity {
	return &sapi.Identity{Sigstore: &sapi.IdentitySigstore{Issuer: githubIssuer, Identity: subject, SourceRepositoryUri: sourceRepo}}
}

// observerIdentity is a githubIdentity whose certificate also records the
// workflow whose run the signer observed (the build config URI).
func observerIdentity(subject, sourceRepo, observed string) *sapi.Identity {
	id := githubIdentity(subject, sourceRepo)
	id.GetSigstore().BuildConfigUri = observed
	return id
}

func googleIdentity(email string) *sapi.Identity {
	return &sapi.Identity{Sigstore: &sapi.IdentitySigstore{Issuer: "https://accounts.google.com", Identity: email}}
}

// TestBuilderBinding runs the builder binding over real generator
// provenance with synthetic signatures: the builder signing its own
// provenance passes, everything else that is signed fails, and an
// unsigned statement is a skip.
func TestBuilderBinding(t *testing.T) {
	t.Parallel()
	v, err := slsa.New()
	require.NoError(t, err)

	for _, tc := range []struct {
		name         string
		fixture      string
		verification *sapi.Verification
		source       string // expected_source param; empty leaves it unset
		want         slsa.Status
		wantMessage  string
	}{
		{
			name: "generator signed its provenance", fixture: "gha-generic-v02-tag.intoto.json",
			verification: verifiedBy(githubIdentity(generatorSubject, "https://github.com/asraa/slsa-on-github-test")),
			source:       "github.com/asraa/slsa-on-github-test", want: slsa.StatusPass, wantMessage: "signed by",
		},
		{
			name: "generator signed, no source expectation", fixture: "gha-generic-v02-tag.intoto.json",
			verification: verifiedBy(githubIdentity(generatorSubject, "https://github.com/asraa/slsa-on-github-test")),
			want:         slsa.StatusPass,
		},
		{
			name: "generator signed at another release", fixture: "gha-generic-v02-tag.intoto.json",
			verification: verifiedBy(githubIdentity("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v1.2.3", "")),
			want:         slsa.StatusFail, wantMessage: `signed by it at "refs/tags/v1.2.3"`,
		},
		{
			name: "signed by another workflow", fixture: "gha-generic-v02-tag.intoto.json",
			verification: verifiedBy(githubIdentity("https://github.com/evil/repo/.github/workflows/build.yml@refs/heads/main", "https://github.com/evil/repo")),
			want:         slsa.StatusFail, wantMessage: "https://github.com/evil/repo/.github/workflows/build.yml",
		},
		{
			name: "signed by a person", fixture: "gha-generic-v02-tag.intoto.json",
			verification: verifiedBy(googleIdentity("user@example.com")),
			want:         slsa.StatusFail, wantMessage: "not its signer",
		},
		{
			name: "certificate from another source repository", fixture: "gha-generic-v02-tag.intoto.json",
			verification: verifiedBy(githubIdentity(generatorSubject, "https://github.com/evil/repo")),
			source:       "github.com/asraa/slsa-on-github-test", want: slsa.StatusFail, wantMessage: "not the expected source",
		},
		{
			name: "builder ran from a branch", fixture: "gha-go-v02-branch.intoto.json",
			verification: verifiedBy(githubIdentity(goBuilderMain, "https://github.com/slsa-framework/example-package")),
			want:         slsa.StatusFail, wantMessage: "not a release tag",
		},
		{
			name: "delegator signed for a custom builder", fixture: "gha-delegator-v1-tag.intoto.json",
			verification: verifiedBy(githubIdentity(delegatorSubject, "https://github.com/slsa-framework/example-package")),
			source:       "github.com/slsa-framework/example-package", want: slsa.StatusPass, wantMessage: "delegator",
		},
		{
			name: "custom builder signed its own provenance", fixture: "gha-delegator-v1-tag.intoto.json",
			verification: verifiedBy(githubIdentity(trwSubject, "https://github.com/slsa-framework/example-package")),
			want:         slsa.StatusPass,
		},
		{
			name: "GitHub attestation signed by its workflow", fixture: "github-attestation-v1-branch.intoto.json",
			verification: verifiedBy(githubIdentity(bcrSubject, "https://github.com/aspect-build/rules_lint")),
			source:       "https://github.com/aspect-build/rules_lint", want: slsa.StatusPass,
		},
		{
			name: "GitHub attestation signed by another workflow", fixture: "github-attestation-v1-branch.intoto.json",
			verification: verifiedBy(githubIdentity("https://github.com/aspect-build/rules_lint/.github/workflows/release.yml@refs/heads/main", "https://github.com/aspect-build/rules_lint")),
			want:         slsa.StatusFail, wantMessage: "builder.id is",
		},
		{
			// tejolote names the builder at the commit it ran from, the
			// certificate at the tag: the same workflow, not a mismatch.
			name: "builder named at a commit, signed at the tag", fixture: "tejolote-v1-tag.intoto.json",
			verification: verifiedBy(githubIdentity(bndRelease, "https://github.com/carabiner-dev/bnd")),
			source:       "github.com/carabiner-dev/bnd", want: slsa.StatusPass,
		},
		{
			name: "builder named at a commit, signed by another workflow", fixture: "tejolote-v1-tag.intoto.json",
			verification: verifiedBy(githubIdentity("https://github.com/carabiner-dev/bnd/.github/workflows/tests.yaml@refs/tags/v0.4.4", "https://github.com/carabiner-dev/bnd")),
			want:         slsa.StatusFail, wantMessage: "builder.id is",
		},
		{
			// The attester (an observer) signed provenance for the workflow
			// its certificate says it observed: builder.id is proven.
			name: "observer signed for the workflow it observed", fixture: "attester-watcher-v1-tag.intoto.json",
			verification: verifiedBy(observerIdentity(attesterSubject, "https://github.com/slsa-framework/attester", attesterObserved)),
			source:       "github.com/slsa-framework/attester", want: slsa.StatusPass, wantMessage: "observer",
		},
		{
			name: "observer certificate names another workflow", fixture: "attester-watcher-v1-tag.intoto.json",
			verification: verifiedBy(observerIdentity(attesterSubject, "https://github.com/slsa-framework/attester",
				"https://github.com/evil/repo/.github/workflows/release.yaml@refs/tags/v0.1.0-rc.3")),
			want: slsa.StatusFail, wantMessage: "observed the run of",
		},
		{
			name: "observer certificate names the workflow at another ref", fixture: "attester-watcher-v1-tag.intoto.json",
			verification: verifiedBy(observerIdentity(attesterSubject, "https://github.com/slsa-framework/attester",
				"https://github.com/slsa-framework/attester/.github/workflows/release.yaml@refs/heads/main")),
			want: slsa.StatusFail, wantMessage: "its run was at",
		},
		{
			// An older certificate without the build config extension
			// cannot prove which run the observer attested.
			name: "observer certificate without build config", fixture: "attester-watcher-v1-tag.intoto.json",
			verification: verifiedBy(githubIdentity(attesterSubject, "https://github.com/slsa-framework/attester")),
			want:         slsa.StatusFail, wantMessage: "does not say which workflow",
		},
		{
			name: "observer certificate from another source repository", fixture: "attester-watcher-v1-tag.intoto.json",
			verification: verifiedBy(observerIdentity(attesterSubject, "https://github.com/evil/repo", attesterObserved)),
			source:       "github.com/slsa-framework/attester", want: slsa.StatusFail, wantMessage: "not the expected source",
		},
		{
			name: "second signer binds", fixture: "gha-generic-v02-tag.intoto.json",
			verification: verifiedBy(googleIdentity("user@example.com"), githubIdentity(generatorSubject, "")),
			want:         slsa.StatusPass,
		},
		{
			name: "unsigned", fixture: "gha-generic-v02-tag.intoto.json",
			verification: nil, want: slsa.StatusSkipped, wantMessage: "no verified signature",
		},
		{
			// A FAILED signature refuses the whole run (see
			// TestVerifySignatureConclusions); an UNVERIFIABLE one is
			// present but proves nothing, so the binding skips.
			name: "signature not verified", fixture: "gha-generic-v02-tag.intoto.json",
			verification: &sapi.Verification{Signature: &sapi.SignatureVerification{Verified: false, Status: sapi.VerificationStatus_UNVERIFIABLE, Identities: []*sapi.Identity{githubIdentity(generatorSubject, "")}}},
			want:         slsa.StatusSkipped,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stmt := &signedAs{Statement: loadFixture(t, tc.fixture), verification: tc.verification}
			opts := []slsa.VerificationOption{
				slsa.WithParam("trusted_builders", []string{"unused"}),
				slsa.WithSkipBuildTypeChecks(true),
			}
			if tc.source != "" {
				opts = append(opts, slsa.WithParam("expected_source", tc.source))
			}
			res, err := v.Verify(context.Background(), stmt, opts...)
			require.NoError(t, err)
			cr := coreResult(t, res, slsa.BuilderBindingControlID)
			assert.Equal(t, tc.want, cr.Status, cr.Message)
			assert.Equal(t, 2, cr.SLSALevel)
			if tc.wantMessage != "" {
				assert.Contains(t, cr.Message, tc.wantMessage)
			}
			if tc.want == slsa.StatusFail {
				assert.Equal(t, slsa.StatusFail, res.Status)
				assert.Less(t, res.SLSALevel, 2, "a failed binding caps the level below L2")
			}
			if tc.verification == nil {
				assert.NotContains(t, res.Message, "unproven", "an unsigned statement is not announced as unproven")
				assert.Contains(t, res.Message, "content alone")
			}
		})
	}
}

// A builder the registry does not know, signed by an identity no known
// builder uses, is accepted with builder.id reported unproven; naming
// the signer as expected binds it; registering its signer binds it too.
func TestBuilderBindingUnbound(t *testing.T) {
	t.Parallel()
	v, err := slsa.New()
	require.NoError(t, err)
	stmt := &signedAs{Statement: loadFixture(t, "v1-build.intoto.json"), verification: verifiedBy(googleIdentity("user@example.com"))}
	params := []slsa.VerificationOption{
		slsa.WithParam("expected_source", "git+https://example.com/repo"),
		slsa.WithParam("trusted_builders", []string{"https://example.com/builder"}),
	}

	res, err := v.Verify(context.Background(), stmt, params...)
	require.NoError(t, err)
	cr := coreResult(t, res, slsa.BuilderBindingControlID)
	assert.Equal(t, slsa.StatusSkipped, cr.Status)
	assert.Contains(t, cr.Message, "unproven")
	assert.Contains(t, cr.Message, "user@example.com")
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 3, res.SLSALevel)
	assert.Contains(t, res.Message, "unproven", "an unproven builder is said out loud in the result")

	// Naming the signer as expected binds the builder to it.
	expected, err := sapi.NewIdentityFromSpec("sigstore::https://accounts.google.com::user@example.com")
	require.NoError(t, err)
	res, err = v.Verify(context.Background(), stmt, append(params, slsa.WithExpectedSigner(expected))...)
	require.NoError(t, err)
	cr = coreResult(t, res, slsa.BuilderBindingControlID)
	assert.Equal(t, slsa.StatusPass, cr.Status, cr.Message)
	assert.Contains(t, cr.Message, "an expected signer")
	assert.Empty(t, res.Message)

	// An expected signer does not override what the registry knows: a
	// known builder must still be signed by its own signer.
	generator := &signedAs{Statement: loadFixture(t, "gha-generic-v02-tag.intoto.json"), verification: verifiedBy(googleIdentity("user@example.com"))}
	res, err = v.Verify(context.Background(), generator,
		slsa.WithParam("trusted_builders", []string{"unused"}), slsa.WithSkipBuildTypeChecks(true), slsa.WithExpectedSigner(expected))
	require.NoError(t, err)
	cr = coreResult(t, res, slsa.BuilderBindingControlID)
	assert.Equal(t, slsa.StatusFail, cr.Status, cr.Message)
	assert.Contains(t, cr.Message, "not its signer")

	// Registering the builder's signer binds it.
	registry, err := builders.LoadEmbedded()
	require.NoError(t, err)
	binding, err := builders.ParseBinding("https://example.com/builder=sigstore::https://accounts.google.com::user@example.com")
	require.NoError(t, err)
	require.NoError(t, registry.Add(binding))
	bound, err := slsa.New(slsa.WithBuilders(registry))
	require.NoError(t, err)
	res, err = bound.Verify(context.Background(), stmt, params...)
	require.NoError(t, err)
	cr = coreResult(t, res, slsa.BuilderBindingControlID)
	assert.Equal(t, slsa.StatusPass, cr.Status, cr.Message)
	assert.Empty(t, res.Message)

	// The bound builder signed by someone else is a failure, not unproven.
	other := &signedAs{Statement: loadFixture(t, "v1-build.intoto.json"), verification: verifiedBy(googleIdentity("other@example.com"))}
	res, err = bound.Verify(context.Background(), other, params...)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusFail, coreResult(t, res, slsa.BuilderBindingControlID).Status)
}

// Source provenance names no builder, so there is nothing to bind.
func TestBuilderBindingSkipsStatementsWithoutBuilder(t *testing.T) {
	t.Parallel()
	v, err := slsa.New()
	require.NoError(t, err)
	stmt := &signedAs{Statement: loadFixture(t, "source.intoto.json"), verification: verifiedBy(googleIdentity("user@example.com"))}
	res, err := v.Verify(context.Background(), stmt,
		slsa.WithParam("expected_source_repo", "https://github.com/example/repo"),
		slsa.WithParam("expected_branch", "refs/heads/main"),
	)
	require.NoError(t, err)
	for _, cr := range res.CoreResults {
		assert.NotEqual(t, slsa.BuilderBindingControlID, cr.ID)
	}
}

// A refuted signature fails the run whether or not signatures are
// required; unsigned and unverifiable statements verify content-only
// with a notice saying so.
func TestVerifySignatureConclusions(t *testing.T) {
	t.Parallel()
	v, err := slsa.New()
	require.NoError(t, err)
	params := []slsa.VerificationOption{
		slsa.WithParam("expected_source", "git+https://example.com/repo"),
		slsa.WithParam("trusted_builders", []string{"https://example.com/builder"}),
	}

	t.Run("refuted always fails", func(t *testing.T) {
		t.Parallel()
		stmt := &signedAs{Statement: loadFixture(t, "v1-build.intoto.json"), verification: &sapi.Verification{
			Signature: &sapi.SignatureVerification{Verified: false, Status: sapi.VerificationStatus_FAILED, Error: "bad sig"},
		}}
		_, err := v.Verify(context.Background(), stmt, params...)
		require.ErrorIs(t, err, slsa.ErrSignatureUnverified)
		assert.Contains(t, err.Error(), "bad sig")
	})
	t.Run("unsigned verifies with a notice", func(t *testing.T) {
		t.Parallel()
		res, err := v.Verify(context.Background(), loadFixture(t, "v1-build.intoto.json"), params...)
		require.NoError(t, err)
		assert.Equal(t, slsa.StatusPass, res.Status)
		assert.Contains(t, res.Message, "unsigned")
		assert.Contains(t, res.Message, "content alone")
	})
	t.Run("unverifiable verifies with the reason", func(t *testing.T) {
		t.Parallel()
		stmt := &signedAs{Statement: loadFixture(t, "v1-build.intoto.json"), verification: &sapi.Verification{
			Signature: &sapi.SignatureVerification{Verified: false, Status: sapi.VerificationStatus_UNVERIFIABLE, Error: "no keys"},
		}}
		res, err := v.Verify(context.Background(), stmt, params...)
		require.NoError(t, err)
		assert.Equal(t, slsa.StatusPass, res.Status)
		assert.Contains(t, res.Message, "no keys")
	})
	t.Run("a verified statement gets no notice", func(t *testing.T) {
		t.Parallel()
		stmt := &signedAs{Statement: loadFixture(t, "v1-build.intoto.json"), verification: verifiedBy(googleIdentity("user@example.com"))}
		res, err := v.Verify(context.Background(), stmt, params...)
		require.NoError(t, err)
		assert.NotContains(t, res.Message, "content alone")
	})
}
