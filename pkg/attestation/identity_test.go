// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"testing"

	cdattestation "github.com/policylabs/attestation"
	sapi "github.com/policylabs/signer/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeVerification stubs the envelope's verification material with
// a configurable identity-matching answer.
type fakeVerification struct {
	verified bool
	matches  bool
}

func (v *fakeVerification) GetVerified() bool          { return v.verified }
func (v *fakeVerification) MatchesIdentity(_ any) bool { return v.matches }

// verifiedEnv is a fakeEnvelope variant that returns a configurable
// Verification. Kept separate from vsa_test.go's fakeEnvelope (which
// returns nil for GetVerification) to avoid affecting other tests.
type verifiedEnv struct {
	*fakeEnvelope
	ver cdattestation.Verification
}

func (e *verifiedEnv) GetVerification() cdattestation.Verification { return e.ver }

func TestVerifyIdentityEmptyExpectedIsNoOp(t *testing.T) {
	t.Parallel()

	err := New().VerifyIdentity(&fakeEnvelope{}, nil)
	assert.NoError(t, err)
}

func TestVerifyIdentityNilEnvelope(t *testing.T) {
	t.Parallel()

	err := New().VerifyIdentity(nil, []*sapi.Identity{{}})
	require.Error(t, err)
}

func TestVerifyIdentityMatchSucceeds(t *testing.T) {
	t.Parallel()

	env := &verifiedEnv{
		fakeEnvelope: &fakeEnvelope{},
		ver:          &fakeVerification{verified: true, matches: true},
	}
	err := New().VerifyIdentity(env, []*sapi.Identity{{}})
	assert.NoError(t, err)
}

func TestVerifyIdentityNoMatchReturnsErr(t *testing.T) {
	t.Parallel()

	env := &verifiedEnv{
		fakeEnvelope: &fakeEnvelope{},
		ver:          &fakeVerification{verified: true, matches: false},
	}
	err := New().VerifyIdentity(env, []*sapi.Identity{{}})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrIdentityMismatch)
}

func TestVerifyIdentityNoVerificationMaterial(t *testing.T) {
	t.Parallel()

	// vsa_test.go's fakeEnvelope returns nil for GetVerification.
	err := New().VerifyIdentity(&fakeEnvelope{}, []*sapi.Identity{{}})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrIdentityMismatch)
}
