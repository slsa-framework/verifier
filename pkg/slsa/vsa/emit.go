// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package vsa

import (
	"errors"
	"fmt"
	"time"

	vsav1 "github.com/in-toto/attestation/go/predicates/vsa/v1"
	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SummaryInput carries the values a verifier needs to emit a VSA v1
// statement summarising its own evaluation. It is the write-side
// counterpart to the read-side Adapter conversions: callers populate it
// from a verification result and call Statement to obtain an unsigned
// in-toto Statement.
type SummaryInput struct {
	// VerifierID is recorded in verifier.id — the identity of the tool
	// that performed the verification.
	VerifierID string

	// TimeVerified is the moment the verification ran. The zero value is
	// omitted from the predicate.
	TimeVerified time.Time

	// Subjects are the in-toto subjects the VSA attests about, normally
	// the subjects of the verified attestation.
	Subjects []*intoto.ResourceDescriptor

	// ResourceURI is the URI of the resource the verification covers
	// (resourceUri). Empty is omitted.
	ResourceURI string

	// PolicyURI, when set, records the policy the verifier evaluated
	// against in policy.uri.
	PolicyURI string

	// PolicyDigest, when set, records the digest of that policy in
	// policy.digest, keyed by algorithm, e.g. {"sha256": "..."}. It
	// requires PolicyURI, because the spec requires policy.uri.
	PolicyDigest map[string]string

	// InputAttestations lists the attestations the verification
	// consumed as evidence (inputAttestations). Each needs a URI and a
	// digest. Empty is omitted.
	InputAttestations []InputAttestation

	// VerificationResult is "PASSED" or "FAILED" (ResultPassed /
	// ResultFailed).
	VerificationResult string

	// VerifiedLevels lists the SLSA levels the verification established,
	// e.g. []string{"SLSA_BUILD_LEVEL_3"}.
	VerifiedLevels []string

	// SLSAVersion records the slsaVersion field; empty is omitted.
	SLSAVersion string
}

// Statement builds an unsigned in-toto Statement wrapping a VSA v1
// predicate from in. The returned statement carries no signature; render
// it with Marshal before writing it out.
func (in *SummaryInput) Statement() (*intoto.Statement, error) {
	if len(in.PolicyDigest) > 0 && in.PolicyURI == "" {
		return nil, errors.New("VSA policy digest without a policy URI")
	}
	if err := validDigest(in.PolicyDigest); err != nil {
		return nil, fmt.Errorf("VSA policy digest: %w", err)
	}
	for i, att := range in.InputAttestations {
		if att.URI == "" || len(att.Digest) == 0 {
			return nil, fmt.Errorf("VSA input attestation %d needs a URI and a digest", i)
		}
		if err := validDigest(att.Digest); err != nil {
			return nil, fmt.Errorf("VSA input attestation %s: %w", att.URI, err)
		}
	}

	pred := &vsav1.VerificationSummary{
		Verifier:           &vsav1.VerificationSummary_Verifier{Id: in.VerifierID},
		ResourceUri:        in.ResourceURI,
		VerificationResult: in.VerificationResult,
		VerifiedLevels:     in.VerifiedLevels,
		SlsaVersion:        in.SLSAVersion,
	}
	if !in.TimeVerified.IsZero() {
		pred.TimeVerified = timestamppb.New(in.TimeVerified)
	}
	if in.PolicyURI != "" {
		pred.Policy = &vsav1.VerificationSummary_Policy{
			Uri:    in.PolicyURI,
			Digest: in.PolicyDigest,
		}
	}
	for _, att := range in.InputAttestations {
		pred.InputAttestations = append(pred.InputAttestations, &vsav1.VerificationSummary_InputAttestation{
			Uri:    att.URI,
			Digest: att.Digest,
		})
	}

	predStruct, err := predicateStruct(pred)
	if err != nil {
		return nil, err
	}

	return &intoto.Statement{
		Type:          intoto.StatementTypeUri,
		Subject:       in.Subjects,
		PredicateType: PredicateTypeV1,
		Predicate:     predStruct,
	}, nil
}

// predicateStruct round-trips the predicate proto through protojson into
// a structpb.Struct so it can be embedded in an in-toto Statement. VSA v1
// round-trips cleanly through protojson (see adapterV1.Convert), so the
// wire form matches the SLSA spec's camelCase field names.
func predicateStruct(pred *vsav1.VerificationSummary) (*structpb.Struct, error) {
	data, err := protojson.Marshal(pred)
	if err != nil {
		return nil, fmt.Errorf("marshaling VSA predicate: %w", err)
	}
	out := &structpb.Struct{}
	if err := protojson.Unmarshal(data, out); err != nil {
		return nil, fmt.Errorf("building VSA predicate struct: %w", err)
	}
	return out, nil
}

// validDigest reports an error for a digest set with an empty algorithm
// or value.
func validDigest(digest map[string]string) error {
	for algorithm, value := range digest {
		if algorithm == "" || value == "" {
			return fmt.Errorf("empty algorithm or value in %v", digest)
		}
	}
	return nil
}

// Marshal renders an in-toto Statement as indented JSON suitable for
// writing to stdout.
func Marshal(stmt *intoto.Statement) ([]byte, error) {
	data, err := protojson.MarshalOptions{Indent: "  "}.Marshal(stmt)
	if err != nil {
		return nil, fmt.Errorf("marshaling VSA statement: %w", err)
	}
	return data, nil
}
