// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package vsa

import (
	"testing"
	"time"

	vsav1 "github.com/in-toto/attestation/go/predicates/vsa/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestIsVSAPredicateType(t *testing.T) {
	t.Parallel()

	assert.True(t, IsVSAPredicateType(PredicateTypeV02))
	assert.True(t, IsVSAPredicateType(PredicateTypeV1))
	assert.False(t, IsVSAPredicateType("https://slsa.dev/provenance/v1"))
	assert.False(t, IsVSAPredicateType(""))
}

func TestPredicateTypesListsBoth(t *testing.T) {
	t.Parallel()

	got := PredicateTypes()
	assert.ElementsMatch(t, []string{PredicateTypeV02, PredicateTypeV1}, got)
}

func TestAdapterV1Convert(t *testing.T) {
	t.Parallel()

	ts := time.Date(2026, time.April, 10, 12, 0, 0, 0, time.UTC)
	src := &vsav1.VerificationSummary{
		Verifier:     &vsav1.VerificationSummary_Verifier{Id: "https://verify.example.com"},
		TimeVerified: timestamppb.New(ts),
		ResourceUri:  "pkg:oci/foo@sha256:abc",
		Policy: &vsav1.VerificationSummary_Policy{
			Uri:    "https://policy.example.com/p",
			Digest: map[string]string{"sha256": "deadbeef"},
		},
		InputAttestations: []*vsav1.VerificationSummary_InputAttestation{
			{Uri: "input-1", Digest: map[string]string{"sha256": "1111"}},
		},
		VerificationResult: ResultPassed,
		VerifiedLevels:     []string{"SLSA_BUILD_LEVEL_3"},
		DependencyLevels:   map[string]uint64{"SLSA_BUILD_LEVEL_2": 5},
		SlsaVersion:        "1.0",
	}

	got, err := FromParsed(PredicateTypeV1, src)
	require.NoError(t, err)
	assert.Equal(t, PredicateTypeV1, got.PredicateType)
	assert.Equal(t, "https://verify.example.com", got.Verifier.ID)
	assert.Equal(t, ts, got.TimeVerified)
	assert.Equal(t, "pkg:oci/foo@sha256:abc", got.ResourceURI)
	assert.Equal(t, "https://policy.example.com/p", got.Policy.URI)
	assert.Equal(t, "deadbeef", got.Policy.Digest["sha256"])
	require.Len(t, got.InputAttestations, 1)
	assert.Equal(t, "input-1", got.InputAttestations[0].URI)
	assert.Equal(t, []string{"SLSA_BUILD_LEVEL_3"}, got.VerifiedLevels)
	assert.Equal(t, uint64(5), got.DependencyLevels["SLSA_BUILD_LEVEL_2"])
	assert.Equal(t, "1.0", got.SLSAVersion)
	assert.True(t, got.Passed())
}

func TestAdapterV02ConvertFoldsPolicyLevel(t *testing.T) {
	t.Parallel()

	src := &v02Payload{
		VerificationResult: ResultPassed,
		ResourceURI:        "pkg:oci/foo@sha256:abc",
		PolicyLevel:        "SLSA_BUILD_LEVEL_3",
	}
	src.Verifier.ID = "https://verify.example.com"
	src.Policy.URI = "https://policy.example.com/p"

	got, err := FromParsed(PredicateTypeV02, src)
	require.NoError(t, err)
	assert.Equal(t, PredicateTypeV02, got.PredicateType)
	assert.Equal(t, "https://verify.example.com", got.Verifier.ID)
	assert.Equal(t, "https://policy.example.com/p", got.Policy.URI)
	assert.Equal(t, []string{"SLSA_BUILD_LEVEL_3"}, got.VerifiedLevels,
		"v0.2 PolicyLevel must be folded into a single-element VerifiedLevels")
	assert.Empty(t, got.SLSAVersion, "v0.2 has no SlsaVersion field")
}

func TestAdapterV02EmptyPolicyLevelLeavesLevelsNil(t *testing.T) {
	t.Parallel()

	src := &v02Payload{VerificationResult: ResultPassed}

	got, err := FromParsed(PredicateTypeV02, src)
	require.NoError(t, err)
	assert.Nil(t, got.VerifiedLevels)
}

func TestFromParsedUnknownPredicateType(t *testing.T) {
	t.Parallel()

	_, err := FromParsed("https://slsa.dev/provenance/v1", &vsav1.VerificationSummary{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotVSA, "expected ErrNotVSA, got %v", err)
}

func TestFromParsedWrongPayloadTypeForRegistered(t *testing.T) {
	t.Parallel()

	// v0.2 payload passed to v1 adapter — should error on type assertion.
	_, err := FromParsed(PredicateTypeV1, &v02Payload{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected")

	// v1 proto passed to v0.2 adapter — same.
	_, err = FromParsed(PredicateTypeV02, &vsav1.VerificationSummary{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected")
}

func TestVSAPassed(t *testing.T) {
	t.Parallel()

	assert.True(t, (&VSA{VerificationResult: ResultPassed}).Passed())
	assert.False(t, (&VSA{VerificationResult: ResultFailed}).Passed())
	assert.False(t, (&VSA{VerificationResult: ""}).Passed())
	assert.False(t, (&VSA{VerificationResult: "passed"}).Passed(), "case-sensitive per spec")
}
