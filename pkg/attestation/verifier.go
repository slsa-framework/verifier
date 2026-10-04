// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	// Importing the SLSA predicate parser registry triggers its init,
	// which replaces the collector's predicate-parser map with the
	// SLSA-only set. Importing the vsa package then layers the VSA
	// parsers on top. Both happen as side effects of these blank
	// imports, so a Verifier built with New() has the right parsers
	// wired up out of the box.
	_ "github.com/slsa-framework/verifier/pkg/slsa/predicate"
	_ "github.com/slsa-framework/verifier/pkg/slsa/vsa"
)

// Verifier orchestrates attestation verification. Methods on the
// Verifier split into two groups:
//
//   - Generic primitives — Load, VerifySignatures, VerifyIdentity —
//     reusable across every supported attestation type.
//   - Per-predicate-family checks — VerifyVSA (and, in time,
//     VerifyBuild / VerifySource) — run the semantic checks for
//     that family against an already-loaded, signature-verified
//     envelope.
//
// The zero value is not usable; construct with New.
type Verifier struct{}

// New returns a Verifier ready to load and verify attestations. It
// takes no required arguments; per-call inputs (keys, expected
// identities, VSA fields, …) flow in via the method-specific Options
// arguments instead of constructor options.
func New() *Verifier {
	return &Verifier{}
}
