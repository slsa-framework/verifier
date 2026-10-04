// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"errors"
	"testing"

	cdattestation "github.com/policylabs/attestation"
	sapi "github.com/policylabs/signer/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signedEnvelope is a fakeEnvelope flavour with a configurable
// signature list, verification result and Verify hook, so signature
// tests can drive the cryptographic path (env.Verify error), the
// recorded-result path (GetVerification) and the policy path
// (Required) without colliding with vsa_test.go's fakeEnvelope
// behaviour.
type signedEnvelope struct {
	*fakeEnvelope
	ver       cdattestation.Verification
	verifyErr error
}

func (e *signedEnvelope) GetVerification() cdattestation.Verification { return e.ver }
func (e *signedEnvelope) Verify(_ ...any) error                       { return e.verifyErr }

func newSignedEnv(sigs []cdattestation.Signature, ver cdattestation.Verification, verifyErr error) *signedEnvelope {
	return &signedEnvelope{
		fakeEnvelope: &fakeEnvelope{sigs: sigs},
		ver:          ver,
		verifyErr:    verifyErr,
	}
}

// fakeSignature is the smallest Signature implementation needed to
// make len(GetSignatures()) non-zero.
type fakeSignature struct{}

func (fakeSignature) GetKeyid() string { return "test-keyid" }
func (fakeSignature) GetSig() []byte   { return []byte("sig") }

var oneSig = []cdattestation.Signature{fakeSignature{}}

// recorded builds the Verification a collector envelope records for a
// conclusion, as VerifyStatement returns it.
func recorded(status sapi.VerificationStatus, reason string) *sapi.Verification {
	return &sapi.Verification{Signature: &sapi.SignatureVerification{
		Status:   status,
		Verified: status == sapi.VerificationStatus_VERIFIED,
		Error:    reason,
	}}
}

func TestVerifySignaturesNilEnvelope(t *testing.T) {
	t.Parallel()

	err := New().VerifySignatures(nil, SignatureOptions{})
	require.Error(t, err)
}

func TestVerifySignaturesRequired(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		sigs    []cdattestation.Signature
		ver     cdattestation.Verification
		wantErr error
		wantMsg string // substring the error must carry, when set
	}{
		{
			name: "unsigned",
			sigs: nil, ver: nil,
			wantErr: ErrSignatureRequired,
		},
		{
			// An envelope that claims to be verified but carries no
			// signatures is still unsigned; the signature check wins.
			name: "unsigned with stray verification",
			sigs: nil, ver: &fakeVerification{verified: true},
			wantErr: ErrSignatureRequired,
		},
		{
			// Signature present, Verify returned nil, but nothing
			// recorded a verified result: no key material was given.
			name: "signed without verification result",
			sigs: oneSig, ver: nil,
			wantErr: ErrSignatureUnverified,
		},
		{
			// Signature present, Verify returned nil, and the envelope
			// recorded a failed verification as a result rather than
			// an error (collector DSSE envelope behaviour).
			name: "signed but verification failed",
			sigs: oneSig, ver: &fakeVerification{verified: false},
			wantErr: ErrSignatureUnverified,
		},
		{
			name: "signed and verified",
			sigs: oneSig, ver: &fakeVerification{verified: true},
			wantErr: nil,
		},
		// Conclusions recorded by the collector carry a status and a
		// reason; the outcome and its message follow them.
		{
			name: "recorded UNSIGNED",
			sigs: oneSig, ver: recorded(sapi.VerificationStatus_UNSIGNED, "DSSE envelope has no signatures"),
			wantErr: ErrSignatureRequired,
		},
		{
			name: "recorded UNVERIFIABLE",
			sigs: oneSig, ver: recorded(sapi.VerificationStatus_UNVERIFIABLE, "no public keys to verify the DSSE signatures against"),
			wantErr: ErrSignatureUnverifiable, wantMsg: "no public keys to verify the DSSE signatures against",
		},
		{
			name: "recorded FAILED",
			sigs: oneSig, ver: recorded(sapi.VerificationStatus_FAILED, "none of the 1 signatures verified against the 1 supplied public keys"),
			wantErr: ErrSignatureUnverified, wantMsg: "none of the 1 signatures verified",
		},
		{
			name: "recorded FAILED without a reason",
			sigs: oneSig, ver: recorded(sapi.VerificationStatus_FAILED, ""),
			wantErr: ErrSignatureUnverified,
		},
		{
			name: "recorded VERIFIED",
			sigs: oneSig, ver: recorded(sapi.VerificationStatus_VERIFIED, ""),
			wantErr: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newSignedEnv(tc.sigs, tc.ver, nil)
			err := New().VerifySignatures(env, SignatureOptions{Required: true})
			if tc.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.ErrorIs(t, err, tc.wantErr, "expected %v, got %v", tc.wantErr, err)
			for _, other := range []error{ErrSignatureRequired, ErrSignatureUnverifiable, ErrSignatureUnverified} {
				if other != tc.wantErr { //nolint:errorlint // comparing sentinels by identity
					require.NotErrorIs(t, err, other)
				}
			}
			if tc.wantMsg != "" {
				assert.Contains(t, err.Error(), tc.wantMsg)
			}
		})
	}
}

func TestVerifySignaturesNotRequired(t *testing.T) {
	t.Parallel()

	// With Required=false a missing or negative signal is not an
	// error: only a failure reported by Verify itself is.
	for _, tc := range []struct {
		name string
		sigs []cdattestation.Signature
		ver  cdattestation.Verification
	}{
		{name: "unsigned", sigs: nil, ver: nil},
		{name: "signed without verification result", sigs: oneSig, ver: nil},
		{name: "signed but verification failed", sigs: oneSig, ver: &fakeVerification{verified: false}},
		{name: "signed and verified", sigs: oneSig, ver: &fakeVerification{verified: true}},
		{name: "recorded UNVERIFIABLE", sigs: oneSig, ver: recorded(sapi.VerificationStatus_UNVERIFIABLE, "no keys")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := newSignedEnv(tc.sigs, tc.ver, nil)
			err := New().VerifySignatures(env, SignatureOptions{Required: false})
			assert.NoError(t, err)
		})
	}
}

// A refuted signature fails whether or not signatures are required:
// unsigned means no claim of integrity, refuted means a false one.
func TestVerifySignaturesRefutedAlwaysFails(t *testing.T) {
	t.Parallel()
	for _, required := range []bool{false, true} {
		env := newSignedEnv(oneSig, recorded(sapi.VerificationStatus_FAILED, "bad sig"), nil)
		err := New().VerifySignatures(env, SignatureOptions{Required: required})
		require.ErrorIs(t, err, ErrSignatureUnverified)
		assert.Contains(t, err.Error(), "bad sig")
	}
}

func TestVerifySignaturesPropagatesEnvelopeError(t *testing.T) {
	t.Parallel()

	want := errors.New("bad signature")
	for _, required := range []bool{false, true} {
		env := newSignedEnv(oneSig, &fakeVerification{verified: true}, want)
		err := New().VerifySignatures(env, SignatureOptions{Required: required})
		require.Error(t, err)
		require.ErrorIs(t, err, want, "required=%v: expected wrapped envelope error, got %v", required, err)
		require.NotErrorIs(t, err, ErrSignatureRequired)
		require.NotErrorIs(t, err, ErrSignatureUnverifiable)
		require.NotErrorIs(t, err, ErrSignatureUnverified)
	}
}
