// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
	"context"
	"fmt"
	"strings"

	"github.com/carabiner-dev/attestation"
	sapi "github.com/carabiner-dev/signer/api/v1"

	"github.com/slsa-framework/verifier/pkg/slsa/builders"
	"github.com/slsa-framework/verifier/pkg/slsa/eval"
)

// BuilderBindingControlID identifies the core result of binding the
// provenance's builder.id to the identity that signed the statement.
const BuilderBindingControlID = "builder-identity-bound"

// builderBindingLevel is the SLSA Build level the binding attests to:
// L2 requires the provenance to be signed by the build platform.
const builderBindingLevel = 2

// CheckBuilder binds the provenance's builder.id to the verified signer
// of the statement using the builder registry, and reports the outcome
// as a core control result:
//
//   - PASS when a verified signer is the builder's signer at an allowed
//     ref (or a delegator's, in which case builder.id names the delegated
//     builder), and the certificate's source repository, when bound and
//     an expected_source param is set, is the expected one;
//   - FAIL when the statement was signed, but not by the builder it
//     claims: another identity, the builder at a disallowed ref, a known
//     builder's workflow claiming a different builder, or a certificate
//     issued to another source repository;
//   - PASS, too, when the registry knows neither builder.id nor the
//     signer but the signer is one of opts.ExpectedSigners: naming the
//     signer you expect binds whatever builder it signs for;
//   - SKIP when the statement carries no verified signature, since the
//     binding needs one; whether that is acceptable is the signature
//     layer's decision;
//   - SKIP, saying builder.id is unproven, when the registry knows
//     neither builder.id nor the signer and no expected signer matches.
//
// Statements without a builder (the source track) produce no result.
func (*defaultImplementation) CheckBuilder(_ context.Context, opts *VerificationOptions, registry *builders.Registry, statement attestation.Statement) (*ControlResult, error) {
	predicate, err := extractPredicate(statement)
	if err != nil {
		return nil, fmt.Errorf("extracting predicate from statement: %w", err)
	}
	builderID := eval.BuilderIDOf(predicate)
	if builderID == "" {
		return nil, nil
	}

	cr := &ControlResult{
		ID:        BuilderBindingControlID,
		Title:     "Provenance Signed by Its Builder",
		SLSALevel: builderBindingLevel,
	}
	signers := verifiedSigners(statement)
	if len(signers) == 0 {
		cr.Status = StatusSkipped
		cr.Message = "the statement carries no verified signature, so builder.id is a claim"
		return cr, nil
	}

	var expectedSource string
	if opts != nil {
		if s, ok := opts.Params["expected_source"].(string); ok {
			expectedSource = s
		}
	}
	known := registry.Lookup(builderID)
	var failure *ControlResult
	for _, signer := range signers {
		outcome := bindBuilder(registry, known, builderID, signer, expectedSource, opts)
		switch outcome.Status {
		case StatusPass:
			cr.Status = StatusPass
			cr.Message = outcome.Message
			return cr, nil
		case StatusFail:
			if failure == nil {
				failure = outcome
			}
		case StatusError, StatusSkipped:
			// Unbound: keep looking for a signer the registry knows.
		}
	}
	if failure != nil {
		cr.Status = StatusFail
		cr.Message = failure.Message
		return cr, nil
	}

	principals := make([]string, 0, len(signers))
	for _, s := range signers {
		principals = append(principals, s.Principal())
	}
	cr.Status = StatusSkipped
	cr.Message = fmt.Sprintf("builder.id %q is unproven: signed by %s, which no known builder uses",
		builderID, strings.Join(principals, ", "))
	return cr, nil
}

// bindBuilder decides whether one verified signer proves builderID.
// known is the registry entry builderID names, if any. The returned
// result is PASS, FAIL, or SKIP when the registry knows neither side
// and the signer is not an expected one.
func bindBuilder(registry *builders.Registry, known *builders.Builder, builderID string, signer *sapi.Identity, expectedSource string, opts *VerificationOptions) *ControlResult {
	entry := registry.ForSigner(signer)
	principal := signer.Principal()
	if entry == nil {
		if known != nil {
			return &ControlResult{Status: StatusFail, Message: fmt.Sprintf(
				"builder.id names %s but the statement was signed by %s, which is not its signer", known.Title, principal)}
		}
		// Neither side is known: the caller naming this signer as one
		// they expect binds the builder to it.
		if isExpectedSigner(signer, opts) {
			return &ControlResult{Status: StatusPass, Message: "signed by " + principal + ", an expected signer"}
		}
		return &ControlResult{Status: StatusSkipped}
	}

	_, signerRef := builders.SplitRef(signerSubject(signer))
	if !entry.Ref.Allows(signerRef) {
		return &ControlResult{Status: StatusFail, Message: fmt.Sprintf(
			"%s signed the statement at %q, which is not a release tag (refs/tags/vX.Y.Z)", entry.Title, signerRef)}
	}

	if entry.Observer {
		// The observer's certificate records the workflow whose run it
		// attested in the build config URI; builder.id must name that
		// workflow, which proves it really ran.
		observed := signer.GetSigstore().GetBuildConfigUri()
		if observed == "" {
			return &ControlResult{Status: StatusFail, Message: fmt.Sprintf(
				"%s signed the statement but its certificate does not say which workflow's run it observed", entry.Title)}
		}
		builderBase, builderRef := builders.SplitRef(builderID)
		observedBase, observedRef := builders.SplitRef(observed)
		if builderBase != observedBase {
			return &ControlResult{Status: StatusFail, Message: fmt.Sprintf(
				"builder.id is %q but the certificate says %s observed the run of %q", builderID, entry.Title, observedBase)}
		}
		if builderRef != "" && observedRef != "" && builderRef != observedRef && !isCommitDigest(builderRef) {
			return &ControlResult{Status: StatusFail, Message: fmt.Sprintf(
				"builder.id names the workflow at %q but the certificate says its run was at %q", builderRef, observedRef)}
		}
	} else if !entry.Delegated {
		// The builder named must be the signer's builder: the entry's
		// id, or for a platform entry, the signer's own subject.
		builderBase, builderRef := builders.SplitRef(builderID)
		signerBase, _ := builders.SplitRef(signerSubject(signer))
		named := entry.MatchesID(builderID)
		if entry.IDMatch == builders.IDMatchPrefix {
			named = builderBase == signerBase
		}
		if !named {
			return &ControlResult{Status: StatusFail, Message: fmt.Sprintf(
				"builder.id is %q but the statement was signed by %s (%s)", builderID, principal, entry.Title)}
		}
		// Some generators name the builder at the commit it ran from
		// (…/release.yaml@<sha>) rather than at the ref the certificate
		// carries; a commit cannot be compared with a ref, and the
		// certificate records no commit to compare it with yet, so
		// only refs are compared.
		if builderRef != "" && signerRef != "" && builderRef != signerRef && !isCommitDigest(builderRef) {
			return &ControlResult{Status: StatusFail, Message: fmt.Sprintf(
				"builder.id names the builder at %q but the statement was signed by it at %q", builderRef, signerRef)}
		}
	}

	if entry.SourceRepositoryBound && expectedSource != "" {
		if certSource := signer.GetSigstore().GetSourceRepositoryUri(); certSource != "" {
			matched, err := eval.RepoMatches(expectedSource, certSource)
			if err != nil {
				return &ControlResult{Status: StatusFail, Message: err.Error()}
			}
			if !matched {
				return &ControlResult{Status: StatusFail, Message: fmt.Sprintf(
					"the signing certificate was issued to a workflow in %s, not the expected source %s", certSource, expectedSource)}
			}
		}
	}

	msg := "signed by " + principal
	if entry.Delegated {
		msg += ", a delegator: builder.id names the delegated builder"
	}
	if entry.Observer {
		msg += ", an observer: its certificate proves the workflow builder.id names ran"
	}
	return &ControlResult{Status: StatusPass, Message: msg}
}

// isCommitDigest reports whether s is a git commit digest (SHA-1 or
// SHA-256 hex) rather than a ref name.
func isCommitDigest(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// isExpectedSigner reports whether signer matches one of the caller's
// expected signer identities.
func isExpectedSigner(signer *sapi.Identity, opts *VerificationOptions) bool {
	if opts == nil {
		return false
	}
	single := &sapi.SignatureVerification{Identities: []*sapi.Identity{signer}}
	for _, expected := range opts.ExpectedSigners {
		if single.MatchesIdentity(expected) {
			return true
		}
	}
	return false
}

// verifiedSigners returns the identities recorded on the statement's
// verification when it verified, nil otherwise.
func verifiedSigners(statement attestation.Statement) []*sapi.Identity {
	v := statement.GetVerification()
	if v == nil || !v.GetVerified() {
		return nil
	}
	sv, ok := v.(interface {
		GetSignature() *sapi.SignatureVerification
	})
	if !ok || sv.GetSignature() == nil {
		return nil
	}
	return sv.GetSignature().GetIdentities()
}

// signerSubject returns the part of a signer identity that may carry a
// ref: the certificate subject for sigstore identities, the principal
// otherwise.
func signerSubject(signer *sapi.Identity) string {
	if s := signer.GetSigstore(); s != nil {
		return s.GetIdentity()
	}
	return signer.Principal()
}
