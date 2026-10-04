// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package vsa

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	vsav1 "github.com/in-toto/attestation/go/predicates/vsa/v1"
	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// TestSummaryInputStatement builds a VSA statement, marshals it, and
// re-parses it to confirm the wire form carries the expected fields and
// is recognised as a VSA v1 predicate.
func TestSummaryInputStatement(t *testing.T) {
	t.Parallel()

	in := SummaryInput{
		VerifierID:         "https://example.com/verifier",
		TimeVerified:       time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC),
		ResourceURI:        "pkg:oci/foo@sha256:abc",
		VerificationResult: ResultPassed,
		VerifiedLevels:     []string{"SLSA_BUILD_LEVEL_3"},
		Subjects: []*intoto.ResourceDescriptor{
			{Name: "foo", Digest: map[string]string{"sha256": "abc"}},
		},
	}

	stmt, err := in.Statement()
	if err != nil {
		t.Fatalf("Statement: %v", err)
	}
	if stmt.GetType() != intoto.StatementTypeUri {
		t.Errorf("type = %q, want %q", stmt.GetType(), intoto.StatementTypeUri)
	}
	if stmt.GetPredicateType() != PredicateTypeV1 {
		t.Errorf("predicateType = %q, want %q", stmt.GetPredicateType(), PredicateTypeV1)
	}
	if got := len(stmt.GetSubject()); got != 1 {
		t.Fatalf("subjects = %d, want 1", got)
	}

	data, err := Marshal(stmt)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Round-trip the marshaled statement back through protojson and pull
	// the predicate out as a VSA v1 proto to confirm field fidelity.
	parsed := &intoto.Statement{}
	if err := protojson.Unmarshal(data, parsed); err != nil {
		t.Fatalf("unmarshal statement: %v", err)
	}
	predJSON, err := protojson.Marshal(parsed.GetPredicate())
	if err != nil {
		t.Fatalf("marshal predicate struct: %v", err)
	}
	pred := &vsav1.VerificationSummary{}
	if err := protojson.Unmarshal(predJSON, pred); err != nil {
		t.Fatalf("unmarshal predicate: %v", err)
	}

	if pred.GetVerifier().GetId() != in.VerifierID {
		t.Errorf("verifier.id = %q, want %q", pred.GetVerifier().GetId(), in.VerifierID)
	}
	if pred.GetVerificationResult() != ResultPassed {
		t.Errorf("verificationResult = %q, want %q", pred.GetVerificationResult(), ResultPassed)
	}
	if pred.GetResourceUri() != in.ResourceURI {
		t.Errorf("resourceUri = %q, want %q", pred.GetResourceUri(), in.ResourceURI)
	}
	if got := pred.GetVerifiedLevels(); len(got) != 1 || got[0] != "SLSA_BUILD_LEVEL_3" {
		t.Errorf("verifiedLevels = %v, want [SLSA_BUILD_LEVEL_3]", got)
	}
	if !pred.GetTimeVerified().AsTime().Equal(in.TimeVerified) {
		t.Errorf("timeVerified = %v, want %v", pred.GetTimeVerified().AsTime(), in.TimeVerified)
	}

	// And confirm the normalized read-side adapter accepts what we emit.
	got, err := FromParsed(PredicateTypeV1, pred)
	if err != nil {
		t.Fatalf("FromParsed: %v", err)
	}
	if !got.Passed() {
		t.Errorf("normalized VSA not passing: %+v", got)
	}
}

// TestSummaryInputStatementOptionalFields checks the wire names of
// policy.digest and inputAttestations, and that neither is emitted when
// unset.
func TestSummaryInputStatementOptionalFields(t *testing.T) {
	t.Parallel()

	base := SummaryInput{
		VerifierID:         "https://example.com/verifier",
		VerificationResult: ResultPassed,
	}
	full := base
	full.PolicyURI = "https://example.com/policy.yaml"
	full.PolicyDigest = map[string]string{"gitCommit": "0123abcd"}
	full.InputAttestations = []InputAttestation{
		{URI: "https://example.com/provenance.json", Digest: map[string]string{"sha256": "abc"}},
	}

	for _, tc := range []struct {
		name string
		in   SummaryInput
		want string
	}{
		{
			name: "unset",
			in:   base,
			want: `{
				"verifier": {"id": "https://example.com/verifier"},
				"verificationResult": "PASSED"
			}`,
		},
		{
			name: "set",
			in:   full,
			want: `{
				"verifier": {"id": "https://example.com/verifier"},
				"policy": {
					"uri": "https://example.com/policy.yaml",
					"digest": {"gitCommit": "0123abcd"}
				},
				"inputAttestations": [{
					"uri": "https://example.com/provenance.json",
					"digest": {"sha256": "abc"}
				}],
				"verificationResult": "PASSED"
			}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stmt, err := tc.in.Statement()
			if err != nil {
				t.Fatalf("Statement: %v", err)
			}
			data, err := Marshal(stmt)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}

			var got struct {
				Predicate map[string]any `json:"predicate"`
			}
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("unmarshal statement: %v", err)
			}
			var want map[string]any
			if err := json.Unmarshal([]byte(tc.want), &want); err != nil {
				t.Fatalf("unmarshal want: %v", err)
			}
			if !reflect.DeepEqual(got.Predicate, want) {
				t.Errorf("predicate = %v, want %v", got.Predicate, want)
			}
		})
	}

	// The read side parses what we emit, including the new fields.
	stmt, err := full.Statement()
	if err != nil {
		t.Fatalf("Statement: %v", err)
	}
	predJSON, err := protojson.Marshal(stmt.GetPredicate())
	if err != nil {
		t.Fatalf("marshal predicate struct: %v", err)
	}
	pred, err := v1Parser{}.Parse(predJSON)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got, err := FromParsed(PredicateTypeV1, pred.GetParsed())
	if err != nil {
		t.Fatalf("FromParsed: %v", err)
	}
	if !reflect.DeepEqual(got.Policy.Digest, full.PolicyDigest) {
		t.Errorf("policy.digest = %v, want %v", got.Policy.Digest, full.PolicyDigest)
	}
	if !reflect.DeepEqual(got.InputAttestations, full.InputAttestations) {
		t.Errorf("inputAttestations = %v, want %v", got.InputAttestations, full.InputAttestations)
	}
}

// TestSummaryInputStatementInvalid checks that a policy digest needs a
// policy URI and input attestations need a URI and a digest, as the spec
// requires.
func TestSummaryInputStatementInvalid(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   SummaryInput
	}{
		{
			name: "policy digest without uri",
			in:   SummaryInput{PolicyDigest: map[string]string{"sha256": "def"}},
		},
		{
			name: "empty policy digest value",
			in:   SummaryInput{PolicyURI: "https://example.com/policy.yaml", PolicyDigest: map[string]string{"sha256": ""}},
		},
		{
			name: "empty input attestation",
			in:   SummaryInput{InputAttestations: []InputAttestation{{}}},
		},
		{
			name: "input attestation without digest",
			in:   SummaryInput{InputAttestations: []InputAttestation{{URI: "https://example.com/provenance.json"}}},
		},
		{
			name: "empty input attestation digest value",
			in: SummaryInput{InputAttestations: []InputAttestation{
				{URI: "https://example.com/provenance.json", Digest: map[string]string{"sha256": ""}},
			}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.in.VerifierID = "https://example.com/verifier"
			tc.in.VerificationResult = ResultPassed
			if _, err := tc.in.Statement(); err == nil {
				t.Fatal("Statement: expected an error")
			}
		})
	}
}
