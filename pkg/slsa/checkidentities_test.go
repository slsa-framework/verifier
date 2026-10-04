// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
	"context"
	"testing"

	"github.com/policylabs/attestation"
	sapi "github.com/policylabs/signer/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signedStmt is a minimal attestation.Statement carrying a verified
// *sapi.Verification with one sigstore identity.
type signedStmt struct {
	verification *sapi.Verification
}

func (*signedStmt) GetSubjects() []attestation.Subject          { return nil }
func (*signedStmt) GetPredicate() attestation.Predicate         { return nil }
func (*signedStmt) GetPredicateType() attestation.PredicateType { return "" }
func (*signedStmt) GetType() string                             { return "" }
func (s *signedStmt) GetVerification() attestation.Verification { return s.verification }

const testIssuer = "https://accounts.google.com"

func newSigstoreVerification(identity string) *sapi.Verification {
	return &sapi.Verification{
		Signature: &sapi.SignatureVerification{
			Verified: true,
			Identities: []*sapi.Identity{{
				Sigstore: &sapi.IdentitySigstore{
					Issuer:   testIssuer,
					Identity: identity,
				},
			}},
		},
	}
}

func TestCheckIdentitiesEmptyListPasses(t *testing.T) {
	t.Parallel()

	impl := &defaultImplementation{}
	err := impl.CheckIdentities(
		context.Background(),
		&VerificationOptions{},
		&signedStmt{},
	)
	require.NoError(t, err)
}

func TestCheckIdentitiesUnsignedReturnsSignatureRequired(t *testing.T) {
	t.Parallel()

	expected, err := sapi.NewIdentityFromSpec(
		"sigstore::https://accounts.google.com::user@example.com",
	)
	require.NoError(t, err)

	impl := &defaultImplementation{}
	err = impl.CheckIdentities(
		context.Background(),
		&VerificationOptions{ExpectedSigners: []*sapi.Identity{expected}},
		&signedStmt{}, // verification is nil
	)
	assert.ErrorIs(t, err, ErrSignatureRequired)
}

func TestCheckIdentitiesMatch(t *testing.T) {
	t.Parallel()

	expected, err := sapi.NewIdentityFromSpec(
		"sigstore::https://accounts.google.com::user@example.com",
	)
	require.NoError(t, err)

	impl := &defaultImplementation{}
	err = impl.CheckIdentities(
		context.Background(),
		&VerificationOptions{ExpectedSigners: []*sapi.Identity{expected}},
		&signedStmt{verification: newSigstoreVerification("user@example.com")},
	)
	require.NoError(t, err)
}

func TestCheckIdentitiesMismatch(t *testing.T) {
	t.Parallel()

	expected, err := sapi.NewIdentityFromSpec(
		"sigstore::https://accounts.google.com::expected@example.com",
	)
	require.NoError(t, err)

	impl := &defaultImplementation{}
	err = impl.CheckIdentities(
		context.Background(),
		&VerificationOptions{ExpectedSigners: []*sapi.Identity{expected}},
		&signedStmt{verification: newSigstoreVerification("someone-else@example.com")},
	)
	assert.ErrorIs(t, err, ErrIdentityMismatch)
}

func TestCheckIdentitiesORMatchAcrossList(t *testing.T) {
	t.Parallel()

	a, err := sapi.NewIdentityFromSpec(
		"sigstore::https://accounts.google.com::a@example.com",
	)
	require.NoError(t, err)
	b, err := sapi.NewIdentityFromSpec(
		"sigstore::https://accounts.google.com::b@example.com",
	)
	require.NoError(t, err)

	impl := &defaultImplementation{}
	// Statement signed by b — second expected signer in list.
	err = impl.CheckIdentities(
		context.Background(),
		&VerificationOptions{ExpectedSigners: []*sapi.Identity{a, b}},
		&signedStmt{verification: newSigstoreVerification("b@example.com")},
	)
	require.NoError(t, err)
}

func TestCheckIdentitiesRegexMatch(t *testing.T) {
	t.Parallel()

	expected, err := sapi.NewIdentityFromSpec(
		"sigstore(identityMatch=regex)::https://accounts.google.com::.*@example\\.com",
	)
	require.NoError(t, err)

	impl := &defaultImplementation{}
	err = impl.CheckIdentities(
		context.Background(),
		&VerificationOptions{ExpectedSigners: []*sapi.Identity{expected}},
		&signedStmt{verification: newSigstoreVerification("alice@example.com")},
	)
	require.NoError(t, err)
}
