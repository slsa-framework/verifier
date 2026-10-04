// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
	"context"
	"testing"

	"github.com/policylabs/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubVerification is a minimal attestation.Verification used by
// VerifySignatures tests in this internal package.
type stubVerification struct {
	verified bool
}

func (s *stubVerification) GetVerified() bool        { return s.verified }
func (s *stubVerification) MatchesIdentity(any) bool { return false }

// stubStmt is a minimal attestation.Statement carrying only the
// verification field (everything else returns zero values).
type stubStmt struct {
	verification attestation.Verification
}

func (*stubStmt) GetSubjects() []attestation.Subject          { return nil }
func (*stubStmt) GetPredicate() attestation.Predicate         { return nil }
func (*stubStmt) GetPredicateType() attestation.PredicateType { return "" }
func (*stubStmt) GetType() string                             { return "" }
func (s *stubStmt) GetVerification() attestation.Verification { return s.verification }

func TestVerifySignaturesPassWhenNotRequired(t *testing.T) {
	t.Parallel()

	impl := &defaultImplementation{}
	err := impl.VerifySignatures(
		context.Background(),
		&VerificationOptions{RequireSignatures: false},
		&stubStmt{},
	)
	require.NoError(t, err)
}

func TestVerifySignaturesFailWhenRequiredAndMissing(t *testing.T) {
	t.Parallel()

	impl := &defaultImplementation{}
	err := impl.VerifySignatures(
		context.Background(),
		&VerificationOptions{RequireSignatures: true},
		&stubStmt{},
	)
	assert.ErrorIs(t, err, ErrSignatureRequired)
}

func TestVerifySignaturesFailWhenRequiredAndUnverified(t *testing.T) {
	t.Parallel()

	impl := &defaultImplementation{}
	err := impl.VerifySignatures(
		context.Background(),
		&VerificationOptions{RequireSignatures: true},
		&stubStmt{verification: &stubVerification{verified: false}},
	)
	assert.ErrorIs(t, err, ErrSignatureRequired)
}

func TestVerifySignaturesPassWhenRequiredAndVerified(t *testing.T) {
	t.Parallel()

	impl := &defaultImplementation{}
	err := impl.VerifySignatures(
		context.Background(),
		&VerificationOptions{RequireSignatures: true},
		&stubStmt{verification: &stubVerification{verified: true}},
	)
	require.NoError(t, err)
}
