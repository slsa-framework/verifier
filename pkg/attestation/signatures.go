// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"errors"
	"fmt"

	cdattestation "github.com/policylabs/attestation"
	sapi "github.com/policylabs/signer/api/v1"
	"github.com/policylabs/signer/key"
	signeroptions "github.com/policylabs/signer/options"
)

// ErrSignatureRequired is returned by VerifySignatures when the
// envelope is unsigned and SignatureOptions.Required is true. It is
// a verification outcome rather than an execution error — callers
// should translate it to their domain's "verification failed" exit
// path (e.g. exit code 1) rather than treating it as a setup
// problem.
var ErrSignatureRequired = errors.New("envelope is unsigned and signatures are required")

// ErrSignatureUnverifiable is returned by VerifySignatures when the
// envelope carries signatures but the verifier had nothing to check
// them against: no --key for a DSSE envelope, or no configured
// verifier for the bundle's kind. The signature was neither confirmed
// nor refuted. Callers may treat it as a configuration problem rather
// than a verification failure.
var ErrSignatureUnverifiable = errors.New("envelope is signed but cannot be verified")

// ErrSignatureUnverified is returned by VerifySignatures when the
// envelope carries signatures that were checked against the available
// key or trust material and did not verify. When the envelope records
// a reason, the returned error wraps this sentinel and carries it.
// Like ErrSignatureRequired it is a verification outcome, not an
// execution error.
var ErrSignatureUnverified = errors.New("envelope signature did not verify")

// SignatureOptions parameterizes VerifySignatures. Keys are passed
// to the envelope's Verify implementation; Required toggles the
// "unsigned → error" policy independent of any keys.
type SignatureOptions struct {
	// Keys is the set of public-key providers used to verify DSSE
	// signatures on the envelope. Sigstore bundles verify against an
	// embedded trust root regardless and do not require entries here.
	Keys []key.PublicKeyProvider

	// RekorVerification enables verifying keyless DSSE envelopes — ones
	// carrying a Sigstore certificate on their signatures — against the
	// Rekor transparency log at RekorURL (the signer's default instance
	// when empty). An unreachable log records the envelope as
	// unverifiable rather than failing the call.
	RekorVerification bool

	// RekorURL is the transparency log to query; empty means the
	// signer's default.
	RekorURL string

	// Required, when true, makes VerifySignatures return
	// ErrSignatureRequired if the envelope carries zero signatures,
	// ErrSignatureUnverifiable if it carries signatures the verifier
	// had no material to check, and ErrSignatureUnverified if the
	// signatures were checked and did not verify. Use this to enforce
	// a "must be signed and verified" policy.
	Required bool
}

// VerifySignatures runs the envelope's cryptographic signature
// verification and, when opts.Required is set, also enforces that
// the envelope is signed and that the signature verified. The checks
// are kept in one method because callers nearly always want both:
// running verification on whatever signatures are present, and
// demanding a verified signature when policy requires it.
//
// A missing signal is not an error on its own: an unsigned envelope,
// or a signed one with no key material to check it against, passes
// when opts.Required is false. Errors from the envelope's Verify
// implementation (signature/key mismatches, trust-root failures for
// Sigstore bundles) always propagate.
//
// With opts.Required set, the verdict is read from the Verification the
// envelope recorded rather than from the presence of signatures, since
// envelope implementations record a failed verification as a result
// instead of returning an error from Verify. It returns
// ErrSignatureRequired when the envelope carries no signatures,
// ErrSignatureUnverifiable when it carries signatures the verifier had
// no key or trust material to check, and ErrSignatureUnverified — with
// the recorded reason, when there is one — when they were checked and
// did not verify.
func (*Verifier) VerifySignatures(env Envelope, opts SignatureOptions) error {
	if env == nil {
		return errors.New("nil envelope")
	}
	verifyArgs := []any{opts.Keys}
	if opts.RekorVerification {
		verifyArgs = append(verifyArgs,
			signeroptions.WithRekorVerification(true),
			signeroptions.WithRekorURL(opts.RekorURL),
		)
	}
	if err := env.Verify(verifyArgs...); err != nil {
		return fmt.Errorf("verifying envelope signatures: %w", err)
	}
	// A signature that was checked and refuted always fails, required
	// or not: unsigned means no claim of integrity, refuted means a
	// claim of integrity that is false.
	if status, reason := recordedStatus(env.GetVerification()); status == sapi.VerificationStatus_FAILED {
		return withReason(ErrSignatureUnverified, reason)
	}
	if !opts.Required {
		return nil
	}
	if len(env.GetSignatures()) == 0 {
		return ErrSignatureRequired
	}
	v := env.GetVerification()
	if v != nil && v.GetVerified() {
		return nil
	}

	status, reason := recordedStatus(v)
	switch status {
	case sapi.VerificationStatus_UNSIGNED:
		return ErrSignatureRequired
	case sapi.VerificationStatus_UNVERIFIABLE:
		return withReason(ErrSignatureUnverifiable, reason)
	case sapi.VerificationStatus_FAILED, sapi.VerificationStatus_UNSPECIFIED, sapi.VerificationStatus_VERIFIED:
		// FAILED, or a verification that recorded no status (VERIFIED
		// with GetVerified false cannot happen, but is not vouched for
		// either): the signatures are there and nothing vouches for them.
		return withReason(ErrSignatureUnverified, reason)
	default:
		return withReason(ErrSignatureUnverified, reason)
	}
}

// recordedStatus returns the status and reason an envelope's Verification
// recorded, when it carries them (the signer's api/v1 Verification does),
// and VerificationStatus_UNSPECIFIED otherwise.
func recordedStatus(v cdattestation.Verification) (status sapi.VerificationStatus, reason string) {
	if v == nil {
		return sapi.VerificationStatus_UNSPECIFIED, ""
	}
	sv, ok := v.(interface {
		GetSignature() *sapi.SignatureVerification
	})
	if !ok || sv.GetSignature() == nil {
		return sapi.VerificationStatus_UNSPECIFIED, ""
	}
	return sv.GetSignature().GetStatus(), sv.GetSignature().GetError()
}

// withReason wraps a verification outcome with the reason the envelope
// recorded, when there is one.
func withReason(outcome error, reason string) error {
	if reason == "" {
		return outcome
	}
	return fmt.Errorf("%w: %s", outcome, reason)
}
