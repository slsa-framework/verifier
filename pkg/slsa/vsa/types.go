// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

// Package vsa provides a version-neutral in-memory representation of
// SLSA Verification Summary Attestations and the adapters that map
// the on-the-wire proto types (vsa/v0.2, vsa/v1, …) onto it.
//
// Adding support for a new VSA version is a single-file change: drop
// in an Adapter implementation that knows how to read the new proto
// and populate VSA, and register it with init(). Verification code
// always reads from VSA — never from version-specific protos — so it
// is insulated from upstream schema churn.
package vsa

import "time"

// Result values defined by the SLSA spec for the VSA
// verificationResult field.
const (
	ResultPassed = "PASSED"
	ResultFailed = "FAILED"
)

// VSA is the version-neutral in-memory representation of a SLSA
// Verification Summary Attestation predicate. Every supported VSA
// predicate version is converted to this shape via a registered
// Adapter before any verification logic runs against it.
//
// Field semantics follow VSA v1; v0.2-only differences are folded in
// by the v0.2 adapter (e.g. the single PolicyLevel becomes a
// one-element VerifiedLevels slice; SLSAVersion stays empty).
type VSA struct {
	// PredicateType is the URI of the source predicate the adapter
	// converted from, e.g. "https://slsa.dev/verification_summary/v1".
	PredicateType string

	Verifier           Verifier
	TimeVerified       time.Time
	ResourceURI        string
	Policy             Policy
	InputAttestations  []InputAttestation
	VerificationResult string
	VerifiedLevels     []string
	DependencyLevels   map[string]uint64

	// SLSAVersion is empty for v0.2 VSAs (the field does not exist in
	// that schema).
	SLSAVersion string
}

// Verifier identifies the entity that produced the VSA.
type Verifier struct {
	ID string
}

// Policy describes the policy the verifier evaluated the subject
// against. Digest is keyed by hash algorithm (e.g. "sha256") and
// will be empty if the producer didn't include digests.
type Policy struct {
	URI    string
	Digest map[string]string
}

// InputAttestation references one of the attestations consumed by
// the verifier as evidence.
type InputAttestation struct {
	URI    string
	Digest map[string]string
}

// Passed reports whether the VSA's verificationResult indicates a
// passing outcome. A VSA where the producer set anything other than
// "PASSED" is treated as a non-passing claim.
func (v *VSA) Passed() bool {
	return v.VerificationResult == ResultPassed
}
