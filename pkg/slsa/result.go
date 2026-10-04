// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package slsa

import "github.com/slsa-framework/verifier/pkg/subject"

// Status enumerates the high-level outcome of a verification or a single control.
type Status string

const (
	// StatusPass means the verification or control evaluation succeeded.
	StatusPass Status = "PASS"

	// StatusFail means the verification or control evaluation failed.
	StatusFail Status = "FAIL"

	// StatusError means the control evaluation produced an error during evaluation
	// (distinct from a clean false outcome).
	StatusError Status = "ERROR"

	// StatusSkipped means none of the control's checks applied to the
	// statement (predicate type or buildTypes mismatch). Skipped
	// controls do not contribute to PASS/FAIL or SLSA-level computation.
	StatusSkipped Status = "SKIP"
)

// ControlResult captures the outcome of evaluating a single control.
type ControlResult struct {
	ID        string
	Title     string
	SLSALevel int
	Status    Status
	Message   string
}

// Result is the final verification outcome returned to callers.
type Result struct {
	// Status is the aggregate outcome derived from all evaluated controls.
	Status Status

	// SLSALevel is the highest SLSA level whose required core controls all passed.
	SLSALevel int

	// Message explains a failing Status that is not attributable to a
	// single control, such as the computed level falling short of the
	// required minimum. Empty otherwise.
	Message string

	// VerifierID is the identity of the entity that performed the
	// verification, copied from VerificationOptions.VerifierID. It is used
	// as verifier.id when a VSA is emitted from this result.
	VerifierID string

	// SpecVersion is the SLSA spec version whose criteria the statement
	// was evaluated against which is the version the requested SpecVersion
	// resolved to in the catalog (eg "1.2"). It surfaces as
	// slsaVersion when a VSA is emitted from this result.
	SpecVersion string

	// CoreResults holds per-control results for the SLSA spec-defined controls.
	CoreResults []*ControlResult

	// BuildTypeResults holds per-control results for custom buildType controls.
	BuildTypeResults []*ControlResult

	// UserResults holds per-control results for user-supplied controls.
	UserResults []*ControlResult

	// Subjects holds the outcome of binding the statement to the
	// artifacts the caller holds, one entry per expected subject in the
	// order given (see WithSubjects). Empty when no subjects were
	// expected. Any unmatched entry makes Status a FAIL.
	Subjects []subject.Match
}

// Pass reports whether the result is a PASS.
func (r *Result) Pass() bool {
	return r != nil && r.Status == StatusPass
}
