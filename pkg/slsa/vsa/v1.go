// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package vsa

import (
	"fmt"

	vsav1 "github.com/in-toto/attestation/go/predicates/vsa/v1"
)

// PredicateTypeV1 is the predicate-type URI for SLSA VSA v1.
const PredicateTypeV1 = "https://slsa.dev/verification_summary/v1"

type adapterV1 struct{}

// PredicateType implements Adapter.
func (adapterV1) PredicateType() string { return PredicateTypeV1 }

// Convert implements Adapter. It expects a *vsav1.VerificationSummary
// — the proto type produced by the v1 parser registered in parsers.go.
// VSA v1 round-trips correctly through protojson because the upstream
// proto definition omits json_name overrides (so protojson uses the
// default camelCase names, matching the SLSA wire format).
func (adapterV1) Convert(parsed any) (*VSA, error) {
	p, ok := parsed.(*vsav1.VerificationSummary)
	if !ok {
		return nil, fmt.Errorf("vsa v1 adapter: expected *vsav1.VerificationSummary, got %T", parsed)
	}

	out := &VSA{
		PredicateType:      PredicateTypeV1,
		ResourceURI:        p.GetResourceUri(),
		VerificationResult: p.GetVerificationResult(),
		VerifiedLevels:     p.GetVerifiedLevels(),
		DependencyLevels:   p.GetDependencyLevels(),
		SLSAVersion:        p.GetSlsaVersion(),
	}
	if v := p.GetVerifier(); v != nil {
		out.Verifier.ID = v.GetId()
	}
	if t := p.GetTimeVerified(); t != nil {
		out.TimeVerified = t.AsTime()
	}
	if pol := p.GetPolicy(); pol != nil {
		out.Policy.URI = pol.GetUri()
		out.Policy.Digest = pol.GetDigest()
	}
	for _, in := range p.GetInputAttestations() {
		out.InputAttestations = append(out.InputAttestations, InputAttestation{
			URI:    in.GetUri(),
			Digest: in.GetDigest(),
		})
	}
	return out, nil
}

func init() { register(adapterV1{}) }
