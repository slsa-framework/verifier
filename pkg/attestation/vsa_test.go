// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"context"
	"strings"
	"testing"

	vsav1 "github.com/in-toto/attestation/go/predicates/vsa/v1"
	intoto "github.com/in-toto/attestation/go/v1"
	cdattestation "github.com/policylabs/attestation"
	sapi "github.com/policylabs/signer/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/verifier/pkg/slsa/vsa"
	"github.com/slsa-framework/verifier/pkg/subject"
)

// fakePredicate is a minimal attestation.Predicate for unit tests —
// only the methods VerifyVSA reaches need real bodies; the rest
// return zero values.
type fakePredicate struct {
	parsed any
	pType  cdattestation.PredicateType
}

func (p *fakePredicate) GetType() cdattestation.PredicateType { return p.pType }
func (p *fakePredicate) SetType(t cdattestation.PredicateType) error {
	p.pType = t
	return nil
}
func (p *fakePredicate) GetParsed() any                               { return p.parsed }
func (p *fakePredicate) GetData() []byte                              { return nil }
func (p *fakePredicate) GetVerification() cdattestation.Verification  { return nil }
func (p *fakePredicate) GetOrigin() cdattestation.Subject             { return nil }
func (p *fakePredicate) SetOrigin(_ cdattestation.Subject)            {}
func (p *fakePredicate) SetVerification(_ cdattestation.Verification) {}

// fakeStmt is a minimal attestation.Statement for unit tests.
type fakeStmt struct {
	pType    cdattestation.PredicateType
	pred     cdattestation.Predicate
	subjects []cdattestation.Subject
}

func (s *fakeStmt) GetSubjects() []cdattestation.Subject          { return s.subjects }
func (s *fakeStmt) GetPredicate() cdattestation.Predicate         { return s.pred }
func (s *fakeStmt) GetPredicateType() cdattestation.PredicateType { return s.pType }
func (s *fakeStmt) GetType() string                               { return "" }
func (s *fakeStmt) GetVerification() cdattestation.Verification   { return nil }

// fakeEnvelope is a minimal attestation.Envelope wrapping a fakeStmt.
// The only methods VerifyVSA touches are GetStatement; the rest
// satisfy the interface with zero values.
type fakeEnvelope struct {
	stmt cdattestation.Statement
	sigs []cdattestation.Signature
}

func (e *fakeEnvelope) GetStatement() cdattestation.Statement       { return e.stmt }
func (e *fakeEnvelope) GetPredicate() cdattestation.Predicate       { return nil }
func (e *fakeEnvelope) GetSignatures() []cdattestation.Signature    { return e.sigs }
func (e *fakeEnvelope) GetCertificate() cdattestation.Certificate   { return nil }
func (e *fakeEnvelope) GetVerification() cdattestation.Verification { return nil }
func (e *fakeEnvelope) Verify(_ ...any) error                       { return nil }

// vsaEnv builds a fake envelope carrying a SLSA VSA v1 proto with
// the fields each test cares about. Optional fields default to
// empty / nil; populate via the modifier.
func vsaEnv(mod func(*vsav1.VerificationSummary)) *fakeEnvelope {
	pred := &vsav1.VerificationSummary{
		Verifier:           &vsav1.VerificationSummary_Verifier{Id: "https://verify.example.com"},
		ResourceUri:        "pkg:oci/foo@sha256:abc",
		VerificationResult: vsa.ResultPassed,
		VerifiedLevels:     []string{"SLSA_BUILD_LEVEL_3"},
		DependencyLevels:   map[string]uint64{"SLSA_BUILD_LEVEL_2": 5},
	}
	if mod != nil {
		mod(pred)
	}
	return &fakeEnvelope{
		stmt: &fakeStmt{
			pType: cdattestation.PredicateType(vsa.PredicateTypeV1),
			pred:  &fakePredicate{pType: cdattestation.PredicateType(vsa.PredicateTypeV1), parsed: pred},
		},
	}
}

func TestVerifyVSAAllChecksPass(t *testing.T) {
	t.Parallel()

	v := New()
	result, err := v.VerifyVSA(context.Background(), vsaEnv(nil), &VSAOptions{
		Verifiers: []VerifierBinding{{ID: "https://verify.example.com"}}, AllowUnbound: true,
		Levels:       []string{"SLSA_BUILD_LEVEL_3"},
		Resource:     "pkg:oci/foo@sha256:abc",
		Dependencies: []string{"SLSA_BUILD_LEVEL_2"},
	})
	require.NoError(t, err)
	assert.True(t, result.Pass(), "expected all checks to pass")
	for _, c := range result.Checks {
		assert.True(t, c.Pass, "check %q should pass", c.Name)
	}
}

func TestVerifyVSAResultMustBePassed(t *testing.T) {
	t.Parallel()

	env := vsaEnv(func(p *vsav1.VerificationSummary) {
		p.VerificationResult = vsa.ResultFailed
	})
	result, err := New().VerifyVSA(context.Background(), env, &VSAOptions{
		Verifiers: []VerifierBinding{{ID: "https://verify.example.com"}}, AllowUnbound: true,
	})
	require.NoError(t, err)
	assert.False(t, result.Pass())
	// The result-PASSED check must be the failing one.
	var failed []string
	for _, c := range result.Checks {
		if !c.Pass {
			failed = append(failed, c.Name)
		}
	}
	require.Len(t, failed, 1)
	assert.Contains(t, failed[0], "Result is PASSED")
}

func TestVerifyVSAVerifierMismatchFails(t *testing.T) {
	t.Parallel()

	result, err := New().VerifyVSA(context.Background(), vsaEnv(nil), &VSAOptions{
		Verifiers: []VerifierBinding{{ID: "https://other.example.com"}}, AllowUnbound: true,
	})
	require.NoError(t, err)
	assert.False(t, result.Pass())
}

func TestVerifyVSALevelOrMatched(t *testing.T) {
	t.Parallel()

	// fixture has verifiedLevels = ["SLSA_BUILD_LEVEL_3"]
	// At-least one of the listed wants must be satisfied. Both pass
	// here (the second is the actual level, the first is below it
	// and is satisfied by at-or-above semantics).
	result, err := New().VerifyVSA(context.Background(), vsaEnv(nil), &VSAOptions{
		Verifiers: []VerifierBinding{{ID: "https://verify.example.com"}}, AllowUnbound: true,
		Levels: []string{"SLSA_BUILD_LEVEL_4", "SLSA_BUILD_LEVEL_3"},
	})
	require.NoError(t, err)
	assert.True(t, result.Pass())
}

func TestVerifyVSALevelAtOrAboveSatisfies(t *testing.T) {
	t.Parallel()

	// VSA reports LEVEL_4, want LEVEL_3 → satisfied.
	env := vsaEnv(func(p *vsav1.VerificationSummary) {
		p.VerifiedLevels = []string{"SLSA_BUILD_LEVEL_4"}
	})
	result, err := New().VerifyVSA(context.Background(), env, &VSAOptions{
		Verifiers: []VerifierBinding{{ID: "https://verify.example.com"}}, AllowUnbound: true,
		Levels: []string{"SLSA_BUILD_LEVEL_3"},
	})
	require.NoError(t, err)
	assert.True(t, result.Pass(),
		"VSA at SLSA_BUILD_LEVEL_4 must satisfy --level SLSA_BUILD_LEVEL_3")
}

func TestVerifyVSALevelBelowWantFails(t *testing.T) {
	t.Parallel()

	// fixture has SLSA_BUILD_LEVEL_3, want LEVEL_4 → fails (3 < 4).
	result, err := New().VerifyVSA(context.Background(), vsaEnv(nil), &VSAOptions{
		Verifiers: []VerifierBinding{{ID: "https://verify.example.com"}}, AllowUnbound: true,
		Levels: []string{"SLSA_BUILD_LEVEL_4"},
	})
	require.NoError(t, err)
	assert.False(t, result.Pass())
}

func TestVerifyVSALevelDifferentTrackFails(t *testing.T) {
	t.Parallel()

	// VSA reports SLSA_BUILD_LEVEL_4; want a SOURCE level. Different
	// track → no satisfaction even at a higher number.
	env := vsaEnv(func(p *vsav1.VerificationSummary) {
		p.VerifiedLevels = []string{"SLSA_BUILD_LEVEL_4"}
	})
	result, err := New().VerifyVSA(context.Background(), env, &VSAOptions{
		Verifiers: []VerifierBinding{{ID: "https://verify.example.com"}}, AllowUnbound: true,
		Levels: []string{"SLSA_SOURCE_LEVEL_3"},
	})
	require.NoError(t, err)
	assert.False(t, result.Pass(),
		"different track must not satisfy regardless of level number")
}

func TestVerifyVSADependenciesAndMatched(t *testing.T) {
	t.Parallel()

	// Every requested key must be present (AND semantics).
	env := vsaEnv(func(p *vsav1.VerificationSummary) {
		p.DependencyLevels = map[string]uint64{"SLSA_BUILD_LEVEL_2": 1}
	})
	result, err := New().VerifyVSA(context.Background(), env, &VSAOptions{
		Verifiers: []VerifierBinding{{ID: "https://verify.example.com"}}, AllowUnbound: true,
		Dependencies: []string{"SLSA_BUILD_LEVEL_2", "SLSA_BUILD_LEVEL_3"},
	})
	require.NoError(t, err)
	assert.False(t, result.Pass(),
		"missing SLSA_BUILD_LEVEL_3 in dependencyLevels must fail when AND-matched")
}

func TestVerifyVSAVerifierRequiredOnOptions(t *testing.T) {
	t.Parallel()

	_, err := New().VerifyVSA(context.Background(), vsaEnv(nil), &VSAOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one verifier")
}

func TestVerifyVSANilEnvelope(t *testing.T) {
	t.Parallel()

	_, err := New().VerifyVSA(context.Background(), nil, &VSAOptions{
		Verifiers: []VerifierBinding{{ID: "https://verify.example.com"}}, AllowUnbound: true,
	})
	require.Error(t, err)
}

func TestVerifyVSANonVSAPredicateReturnsErrNotVSA(t *testing.T) {
	t.Parallel()

	env := &fakeEnvelope{
		stmt: &fakeStmt{
			pType: "https://slsa.dev/provenance/v1",
			pred:  &fakePredicate{pType: "https://slsa.dev/provenance/v1", parsed: nil},
		},
	}
	_, err := New().VerifyVSA(context.Background(), env, &VSAOptions{
		Verifiers: []VerifierBinding{{ID: "https://verify.example.com"}}, AllowUnbound: true,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, vsa.ErrNotVSA, "expected ErrNotVSA, got %v", err)
}

// --- verifier/signer binding -------------------------------------------

// keyID builds an expected identity for a key id, and signedBy an
// envelope carrying a verified signature recorded for that key id.
func keyID(id string) *sapi.Identity {
	return &sapi.Identity{Key: &sapi.IdentityKey{Id: id}}
}

func signedBy(env *fakeEnvelope, keyIDs ...string) *verifiedEnv {
	ids := make([]*sapi.Identity, 0, len(keyIDs))
	for _, id := range keyIDs {
		ids = append(ids, keyID(id))
	}
	return &verifiedEnv{fakeEnvelope: env, ver: &sapi.Verification{Signature: &sapi.SignatureVerification{
		Status: sapi.VerificationStatus_VERIFIED, Verified: true, Identities: ids,
	}}}
}

// claimedBy is a VSA envelope whose predicate claims the given verifier.
func claimedBy(verifier string) *fakeEnvelope {
	return vsaEnv(func(v *vsav1.VerificationSummary) { v.Verifier.Id = verifier })
}

func checkNamed(t *testing.T, r *VSAResult, prefix string) *VSACheck {
	t.Helper()
	for i := range r.Checks {
		if strings.HasPrefix(r.Checks[i].Name, prefix) {
			return &r.Checks[i]
		}
	}
	return nil
}

func TestVerifyVSAUnboundVerifierIsRejectedByDefault(t *testing.T) {
	t.Parallel()

	_, err := New().VerifyVSA(context.Background(), vsaEnv(nil), &VSAOptions{
		Verifiers: []VerifierBinding{{ID: "https://verify.example.com"}},
	})
	require.ErrorIs(t, err, ErrVerifierUnbound)
	assert.Contains(t, err.Error(), "https://verify.example.com")

	// Naming one bound and one unbound verifier is still an error, and
	// the message names the unbound one.
	_, err = New().VerifyVSA(context.Background(), vsaEnv(nil), &VSAOptions{
		Verifiers: []VerifierBinding{
			{ID: "https://bound.example.com", Signers: []*sapi.Identity{keyID("k")}},
			{ID: "https://loose.example.com"},
		},
	})
	require.ErrorIs(t, err, ErrVerifierUnbound)
	assert.Contains(t, err.Error(), "https://loose.example.com")
	assert.NotContains(t, err.Error(), "https://bound.example.com")

	// A wildcard signer binds every verifier.
	r, err := New().VerifyVSA(context.Background(), signedBy(vsaEnv(nil), "k"), &VSAOptions{
		Verifiers: []VerifierBinding{{ID: "https://verify.example.com"}},
		Signers:   []*sapi.Identity{keyID("k")},
	})
	require.NoError(t, err)
	assert.True(t, r.Pass())
}

func TestVerifyVSASignerBinding(t *testing.T) {
	t.Parallel()

	const verifierA, verifierB = "https://a.example.com", "https://b.example.com"
	bound := func() *VSAOptions {
		return &VSAOptions{
			Verifiers: []VerifierBinding{
				{ID: verifierA, Signers: []*sapi.Identity{keyID("key-a")}},
				{ID: verifierB, Signers: []*sapi.Identity{keyID("key-b")}},
			},
			Levels: []string{"SLSA_BUILD_LEVEL_3"},
		}
	}

	for _, tc := range []struct {
		name        string
		env         Envelope
		opts        *VSAOptions
		wantPass    bool
		wantSigner  bool   // the signer check must appear
		wantMessage string // substring of the signer check's failure message
	}{
		{
			name: "A signed by A's signer",
			env:  signedBy(claimedBy(verifierA), "key-a"), opts: bound(),
			wantPass: true, wantSigner: true,
		},
		{
			name: "B signed by B's signer",
			env:  signedBy(claimedBy(verifierB), "key-b"), opts: bound(),
			wantPass: true, wantSigner: true,
		},
		{
			// The case the binding exists for: a signer trusted for A
			// cannot vouch as B.
			name: "B signed by A's signer",
			env:  signedBy(claimedBy(verifierB), "key-a"), opts: bound(),
			wantPass: false, wantSigner: true, wantMessage: "not authorized for this verifier",
		},
		{
			name:     "wildcard signer vouches for either",
			env:      signedBy(claimedBy(verifierB), "key-x"),
			opts:     func() *VSAOptions { o := bound(); o.Signers = []*sapi.Identity{keyID("key-x")}; return o }(),
			wantPass: true, wantSigner: true,
		},
		{
			name:     "a verifier's own signer adds to the wildcard, not replaces it",
			env:      signedBy(claimedBy(verifierA), "key-a"),
			opts:     func() *VSAOptions { o := bound(); o.Signers = []*sapi.Identity{keyID("key-x")}; return o }(),
			wantPass: true, wantSigner: true,
		},
		{
			name: "bound verifier, unsigned envelope",
			env:  claimedBy(verifierA), opts: bound(),
			wantPass: false, wantSigner: true, wantMessage: "no verified signature",
		},
		{
			name: "bound verifier, signature recorded but not verified",
			env: &verifiedEnv{fakeEnvelope: claimedBy(verifierA), ver: &sapi.Verification{Signature: &sapi.SignatureVerification{
				Status: sapi.VerificationStatus_FAILED, Identities: nil,
			}}},
			opts:     bound(),
			wantPass: false, wantSigner: true, wantMessage: "no verified signature",
		},
		{
			// An unaccepted verifier fails the verifier check; there is
			// no binding to check the signer against.
			name: "claimed verifier is not accepted",
			env:  signedBy(claimedBy("https://nobody.example.com"), "key-a"), opts: bound(),
			wantPass: false, wantSigner: false,
		},
		{
			// Unbound and allowed: only the id is matched, no signer row.
			name:     "unbound verifier allowed explicitly",
			env:      claimedBy(verifierA),
			opts:     &VSAOptions{Verifiers: []VerifierBinding{{ID: verifierA}}, AllowUnbound: true},
			wantPass: true, wantSigner: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r, err := New().VerifyVSA(context.Background(), tc.env, tc.opts)
			require.NoError(t, err)
			assert.Equal(t, tc.wantPass, r.Pass(), "checks: %+v", r.Checks)

			signer := checkNamed(t, r, "Signer is authorized for verifier")
			if !tc.wantSigner {
				assert.Nil(t, signer, "no signer check expected")
				return
			}
			require.NotNil(t, signer, "signer check expected")
			assert.Equal(t, tc.wantPass, signer.Pass)
			if tc.wantMessage != "" {
				assert.Contains(t, signer.Message, tc.wantMessage)
			}
		})
	}
}

// The verifier check names every accepted verifier and matches any.
func TestVerifyVSAVerifierOrMatched(t *testing.T) {
	t.Parallel()

	opts := &VSAOptions{
		Verifiers:    []VerifierBinding{{ID: "https://a.example.com"}, {ID: "https://verify.example.com"}},
		AllowUnbound: true,
	}
	r, err := New().VerifyVSA(context.Background(), vsaEnv(nil), opts)
	require.NoError(t, err)
	assert.True(t, r.Pass())
	verifier := checkNamed(t, r, "Verifier is one of")
	require.NotNil(t, verifier)
	assert.Contains(t, verifier.Name, "https://a.example.com")
	assert.Contains(t, verifier.Name, "https://verify.example.com")
}

// --- subject binding ----------------------------------------------------

func TestVerifyVSASubjects(t *testing.T) {
	t.Parallel()

	env := vsaEnv(nil)
	stmt, ok := env.stmt.(*fakeStmt)
	require.True(t, ok)
	stmt.subjects = []cdattestation.Subject{
		&intoto.ResourceDescriptor{Name: "pkg:oci/foo", Digest: map[string]string{"sha256": "aaaa"}},
	}
	opts := func(expected ...*subject.Expected) *VSAOptions {
		return &VSAOptions{
			Verifiers:    []VerifierBinding{{ID: "https://verify.example.com"}},
			AllowUnbound: true,
			Subjects:     expected,
		}
	}
	held := &subject.Expected{Name: "foo.tgz", Digests: map[string]string{"sha256": "aaaa"}}
	other := &subject.Expected{Name: "bar.tgz", Digests: map[string]string{"sha256": "ffff"}}

	// Nothing expected: nothing reported, verdict unchanged.
	r, err := New().VerifyVSA(context.Background(), env, opts())
	require.NoError(t, err)
	assert.True(t, r.Pass())
	assert.Empty(t, r.Subjects)

	// The held artifact is the VSA's subject.
	r, err = New().VerifyVSA(context.Background(), env, opts(held))
	require.NoError(t, err)
	assert.True(t, r.Pass())
	require.Len(t, r.Subjects, 1)
	assert.True(t, r.Subjects[0].Matched)
	assert.Equal(t, "pkg:oci/foo", r.Subjects[0].Subject.GetName())

	// One artifact the VSA is not about fails the result, while every
	// check row still passes and both outcomes are reported.
	r, err = New().VerifyVSA(context.Background(), env, opts(held, other))
	require.NoError(t, err)
	assert.False(t, r.Pass())
	for _, c := range r.Checks {
		assert.True(t, c.Pass, c.Name)
	}
	require.Len(t, r.Subjects, 2)
	assert.True(t, r.Subjects[0].Matched)
	assert.False(t, r.Subjects[1].Matched)
	assert.NotEmpty(t, r.Subjects[1].Message)
}
