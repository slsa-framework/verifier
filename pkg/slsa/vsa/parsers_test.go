// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package vsa

import (
	"testing"

	collectorpred "github.com/carabiner-dev/collector/predicate"
	vsav1 "github.com/in-toto/attestation/go/predicates/vsa/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParsersRegistered confirms our init() hooked both VSA parsers
// into the collector's global registry (and survived pkg/slsa/predicate's
// init() which replaces the map).
func TestParsersRegistered(t *testing.T) {
	t.Parallel()

	assert.NotNil(t, collectorpred.Parsers[PredicateTypeV02], "VSA v0.2 parser must be registered")
	assert.NotNil(t, collectorpred.Parsers[PredicateTypeV1], "VSA v1 parser must be registered")
}

// TestV02ParserAcceptsCamelCase is the regression test for the v0.2
// wire-format quirk: SLSA producers emit camelCase per the spec, but
// the upstream v0.2 proto's json_name overrides force snake_case in
// protojson. Our hand-rolled struct must accept camelCase.
func TestV02ParserAcceptsCamelCase(t *testing.T) {
	t.Parallel()

	camel := []byte(`{
  "verifier": {"id": "https://verify.example.com"},
  "resourceUri": "pkg:oci/foo@sha256:abc",
  "policy": {"uri": "https://policy.example.com/p"},
  "verificationResult": "PASSED",
  "policyLevel": "SLSA_BUILD_LEVEL_2"
}`)
	pred, err := v02Parser{}.Parse(camel)
	require.NoError(t, err)
	p, ok := pred.GetParsed().(*v02Payload)
	require.True(t, ok)
	assert.Equal(t, "https://verify.example.com", p.Verifier.ID)
	assert.Equal(t, "pkg:oci/foo@sha256:abc", p.ResourceURI)
	assert.Equal(t, "https://policy.example.com/p", p.Policy.URI)
	assert.Equal(t, ResultPassed, p.VerificationResult)
	assert.Equal(t, "SLSA_BUILD_LEVEL_2", p.PolicyLevel)
}

// TestV1ParserAcceptsCamelCase confirms v1 parsing through protojson
// works for the camelCase wire format (v1 omits the v0.2 json_name
// overrides, so this should Just Work).
func TestV1ParserAcceptsCamelCase(t *testing.T) {
	t.Parallel()

	camel := []byte(`{
  "verifier": {"id": "https://verify.example.com"},
  "resourceUri": "pkg:oci/foo@sha256:abc",
  "verificationResult": "PASSED",
  "verifiedLevels": ["SLSA_BUILD_LEVEL_3"],
  "slsaVersion": "1.0"
}`)
	pred, err := v1Parser{}.Parse(camel)
	require.NoError(t, err)
	assert.Equal(t, PredicateTypeV1, string(pred.GetType()))
}

// TestV1ParserAcceptsUnknownFields confirms unknown extension fields are tolerated.
func TestV1ParserAcceptsUnknownFields(t *testing.T) {
	t.Parallel()

	payload := []byte(`{
  "verifier": {"id": "https://verify.example.com"},
  "resourceUri": "pkg:oci/foo@sha256:abc",
  "verificationResult": "PASSED",
  "verifiedLevels": ["SLSA_BUILD_LEVEL_3"],
  "slsaVersion": "1.0",
  "//example.com/vsa/verification_global_id": "0x12345678",
  "customProducerField": {"key": "val"}
}`)
	pred, err := v1Parser{}.Parse(payload)
	require.NoError(t, err)
	assert.Equal(t, PredicateTypeV1, string(pred.GetType()))
	msg, ok := pred.GetParsed().(*vsav1.VerificationSummary)
	require.True(t, ok, "parsed type should be *vsav1.VerificationSummary")
	assert.Equal(t, "https://verify.example.com", msg.GetVerifier().GetId())
	assert.Equal(t, "pkg:oci/foo@sha256:abc", msg.GetResourceUri())
	assert.Equal(t, "PASSED", msg.GetVerificationResult())
}
