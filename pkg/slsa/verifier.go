// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package slsa

// The predicate package is imported for its init: it registers the
// SLSA-only predicate parsers as the collector's global registry so
// envelope/statement parsing only recognises SLSA build and source
// predicate types.
import (
	"context"
	"fmt"
	"maps"

	"github.com/carabiner-dev/attestation"
	sapi "github.com/carabiner-dev/signer/api/v1"

	"github.com/slsa-framework/verifier/pkg/slsa/builders"
	"github.com/slsa-framework/verifier/pkg/slsa/controls"
	_ "github.com/slsa-framework/verifier/pkg/slsa/predicate" // registers the SLSA-only predicate parsers
	"github.com/slsa-framework/verifier/pkg/subject"
)

// Verifier is the SLSA attestation verifier. It orchestrates the layered
// verification flow described in the project design, delegating the
// per-layer logic to the configured verifierImplementation.
type Verifier struct {
	impl                       VerifierImplementation
	Options                    Options
	defaultVerificationOptions VerificationOptions
}

// New constructs a Verifier with the embedded control catalog and the
// default verifierImplementation. Pass options to override either.
func New(opts ...Option) (*Verifier, error) {
	impl, err := newDefaultImplementation()
	if err != nil {
		return nil, fmt.Errorf("constructing default implementation: %w", err)
	}
	v := &Verifier{
		impl:                       impl,
		Options:                    DefaultOptions(),
		defaultVerificationOptions: DefaultVerificationOptions(),
	}
	for _, fn := range opts {
		if err := fn(v); err != nil {
			return nil, fmt.Errorf("applying option: %w", err)
		}
	}
	if v.Options.Catalog == nil {
		cat, err := controls.LoadEmbedded()
		if err != nil {
			return nil, fmt.Errorf("loading embedded catalog: %w", err)
		}
		v.Options.Catalog = cat
	}
	if v.Options.Builders == nil {
		reg, err := builders.LoadEmbedded()
		if err != nil {
			return nil, fmt.Errorf("loading embedded builder registry: %w", err)
		}
		v.Options.Builders = reg
	}
	return v, nil
}

// Verify runs the layered verification flow against the given statement
// and returns a Result describing the outcome.
func (v *Verifier) Verify(ctx context.Context, statement attestation.Statement, opts ...VerificationOption) (*Result, error) {
	if statement == nil {
		return nil, fmt.Errorf("statement is required")
	}

	vopts := v.defaultVerificationOptions
	// The struct copy above still shares the default Params map; clone it
	// so WithParam calls don't leak into subsequent Verify calls.
	vopts.Params = maps.Clone(vopts.Params)
	for _, fn := range opts {
		if err := fn(&vopts); err != nil {
			return nil, fmt.Errorf("applying verification option: %w", err)
		}
	}

	// Layer 1: signature verification.
	if err := v.impl.VerifySignatures(ctx, &vopts, statement); err != nil {
		return nil, fmt.Errorf("verifying signatures: %w", err)
	}

	// Layer 2: identity check.
	if err := v.impl.CheckIdentities(ctx, &vopts, statement); err != nil {
		return nil, fmt.Errorf("checking identities: %w", err)
	}

	// Layer 2b: bind the statement to the artifacts the caller holds.
	// A mismatch is a verdict, not an error: the controls still run so
	// the caller sees the full picture, and the result fails below.
	subjects, err := v.impl.CheckSubjects(ctx, &vopts, statement)
	if err != nil {
		return nil, fmt.Errorf("checking subjects: %w", err)
	}

	// Layer 3: predicate routing (build vs source).
	category, err := v.impl.ResolveCategory(&vopts, v.Options.Catalog, statement)
	if err != nil {
		return nil, fmt.Errorf("resolving predicate category: %w", err)
	}

	// Layer 4: select and run core SLSA controls.
	coreCtrls := v.impl.SelectCoreControls(&vopts, v.Options.Catalog, category)
	coreResults, err := v.impl.RunControls(ctx, &vopts, coreCtrls, statement)
	if err != nil {
		return nil, fmt.Errorf("running core controls: %w", err)
	}

	// Layer 4b: bind the builder the provenance names to the identity
	// that signed it. The outcome joins the core roster: signed by the
	// builder is what SLSA Build L2 asks of provenance.
	binding, err := v.impl.CheckBuilder(ctx, &vopts, v.Options.Builders, statement)
	if err != nil {
		return nil, fmt.Errorf("binding builder to signer: %w", err)
	}
	if binding != nil {
		coreResults = append(coreResults, binding)
	}
	// A signed statement whose builder nothing proves is accepted, but
	// said out loud: the roster hides skipped controls by default.
	var notice string
	if binding != nil && binding.Status == StatusSkipped && len(verifiedSigners(statement)) > 0 {
		notice = binding.Message
	}
	// So is a run with no verified signature: without it, a PASS speaks
	// only for the document's content.
	if !vopts.RequireSignatures {
		notice = joinMessages(contentOnlyNotice(statement), notice)
	}

	// Layer 5: select and run buildType controls (optional).
	var buildTypeResults []*ControlResult
	if vopts.RunBuildTypeControls {
		btCtrls := v.impl.SelectBuildTypeControls(&vopts, v.Options.Catalog, statement)
		// A buildType the catalog knows, with no expectation stated for
		// it, is an incomplete invocation rather than a pass.
		run, skipped, err := partitionBuildTypeControls(&vopts, btCtrls, statement)
		if err != nil {
			return nil, err
		}
		buildTypeResults, err = v.impl.RunControls(ctx, &vopts, run, statement)
		if err != nil {
			return nil, fmt.Errorf("running buildType controls: %w", err)
		}
		buildTypeResults = append(buildTypeResults, skipped...)
	}

	// Layer 6: select and run user controls (optional).
	var userResults []*ControlResult
	if vopts.RunUserControls {
		userCtrls := v.impl.SelectUserControls(&vopts)
		userResults, err = v.impl.RunControls(ctx, &vopts, userCtrls, statement)
		if err != nil {
			return nil, fmt.Errorf("running user controls: %w", err)
		}
	}

	// Layer 7: compute the final result.
	result, err := v.impl.ComputeResult(&vopts, coreResults, buildTypeResults, userResults)
	if err != nil {
		return nil, fmt.Errorf("computing result: %w", err)
	}
	if result != nil {
		capBuilderLevel(&vopts, statement, result)
		// Record the spec version the core category resolved to so
		// callers (and emitted VSAs) can state which criteria applied.
		result.SpecVersion = controls.SpecVersionOf(category)
		result.Message = joinMessages(result.Message, notice)
		result.Subjects = subjects
		if !subject.AllMatched(subjects) {
			result.Status = StatusFail
			result.Message = joinMessages(result.Message, subjectsMessage(subjects))
		}
	}
	return result, nil
}

// contentOnlyNotice says a statement was evaluated without a verified
// signature — unsigned, or signed but unverifiable — and why. Empty for
// statements whose signature verified.
func contentOnlyNotice(statement attestation.Statement) string {
	v := statement.GetVerification()
	if v != nil && v.GetVerified() {
		return ""
	}
	sv, ok := v.(interface {
		GetSignature() *sapi.SignatureVerification
	})
	if ok && sv.GetSignature() != nil && sv.GetSignature().GetStatus() == sapi.VerificationStatus_UNVERIFIABLE {
		reason := sv.GetSignature().GetError()
		if reason != "" {
			return "signature not verified (" + reason + "): evaluated on content alone"
		}
		return "signature not verified: evaluated on content alone"
	}
	return "the statement is unsigned: evaluated on content alone"
}

// subjectsMessage summarizes which expected subjects the statement is
// not about.
func subjectsMessage(matches []subject.Match) string {
	unmatched := 0
	for _, m := range matches {
		if !m.Matched {
			unmatched++
		}
	}
	return fmt.Sprintf("%d of %d expected subjects not found in the attestation", unmatched, len(matches))
}

func joinMessages(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + "; " + b
}
