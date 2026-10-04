// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package vsa

import (
	"fmt"
	"time"
)

// PredicateTypeV02 is the predicate-type URI for SLSA VSA v0.2.
const PredicateTypeV02 = "https://slsa.dev/verification_summary/v0.2"

// v02Payload is the on-the-wire shape of a SLSA VSA v0.2 predicate.
// The upstream proto type for this version ships json_name overrides
// that force snake_case in protojson, which conflicts with the
// camelCase format the SLSA v0.2 spec actually defines, so we parse
// through encoding/json into this struct instead.
type v02Payload struct {
	Verifier struct {
		ID string `json:"id"`
	} `json:"verifier"`
	TimeVerified       time.Time         `json:"timeVerified,omitempty"`
	ResourceURI        string            `json:"resourceUri,omitempty"`
	Policy             v02PolicyPayload  `json:"policy"`
	InputAttestations  []v02InputPayload `json:"inputAttestations,omitempty"`
	VerificationResult string            `json:"verificationResult,omitempty"`
	PolicyLevel        string            `json:"policyLevel,omitempty"`
	DependencyLevels   map[string]uint64 `json:"dependencyLevels,omitempty"`
}

type v02PolicyPayload struct {
	URI    string            `json:"uri,omitempty"`
	Digest map[string]string `json:"digest,omitempty"`
}

type v02InputPayload struct {
	URI    string            `json:"uri,omitempty"`
	Digest map[string]string `json:"digest,omitempty"`
}

type adapterV02 struct{}

// PredicateType implements Adapter.
func (adapterV02) PredicateType() string { return PredicateTypeV02 }

// Convert implements Adapter. It expects a *v02Payload — the value
// the v0.2 parser registered in parsers.go produces.
//
// The v0.2 schema carries a single PolicyLevel string instead of v1's
// VerifiedLevels list; the adapter folds it into a one-element
// VerifiedLevels slice on the normalized VSA so downstream code only
// deals with one shape. SLSAVersion stays empty (the field doesn't
// exist in v0.2).
func (adapterV02) Convert(parsed any) (*VSA, error) {
	p, ok := parsed.(*v02Payload)
	if !ok {
		return nil, fmt.Errorf("vsa v0.2 adapter: expected *v02Payload, got %T", parsed)
	}

	out := &VSA{
		PredicateType:      PredicateTypeV02,
		Verifier:           Verifier{ID: p.Verifier.ID},
		TimeVerified:       p.TimeVerified,
		ResourceURI:        p.ResourceURI,
		Policy:             Policy{URI: p.Policy.URI, Digest: p.Policy.Digest},
		VerificationResult: p.VerificationResult,
		DependencyLevels:   p.DependencyLevels,
	}
	for _, in := range p.InputAttestations {
		out.InputAttestations = append(out.InputAttestations, InputAttestation(in))
	}
	if p.PolicyLevel != "" {
		out.VerifiedLevels = []string{p.PolicyLevel}
	}
	return out, nil
}

func init() { register(adapterV02{}) }
