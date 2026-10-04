// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package attestation provides a Verifier object that orchestrates
// loading, signature verification, and per-predicate-type semantic
// verification of in-toto attestations. The shape is one method per
// predicate family (VerifyVSA today, VerifyBuild / VerifySource to
// follow), each built on top of the same generic Load and
// VerifySignatures primitives.
//
// Envelope and Statement are re-exported from
// github.com/policylabs/attestation as type aliases so callers
// only need to import this package.
package attestation

import (
	cdattestation "github.com/policylabs/attestation"
)

// Envelope is an in-toto attestation envelope (bare statement, DSSE,
// or Sigstore bundle). Re-exported from the carabiner attestation
// package as a type alias so callers of this library don't need a
// separate import for the envelope abstraction.
type Envelope = cdattestation.Envelope

// Statement is an in-toto statement (subject + predicate). Re-exported
// from the carabiner attestation package.
type Statement = cdattestation.Statement
