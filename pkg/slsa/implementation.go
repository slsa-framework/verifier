// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

package slsa

import (
	"context"
	"errors"
	"fmt"
	"slices"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	sapi "github.com/policylabs/signer/api/v1"
	"google.golang.org/protobuf/proto"

	"github.com/slsa-framework/verifier/pkg/slsa/builders"
	"github.com/slsa-framework/verifier/pkg/slsa/controls"
	"github.com/slsa-framework/verifier/pkg/slsa/eval"
	"github.com/slsa-framework/verifier/pkg/subject"
)

var ErrNotImplemented = errors.New("slsa: not implemented")

// ErrSignatureRequired is returned when the statement carries no verified
// signature in a context that requires one (RequireSignatures or a
// non-empty ExpectedSigners list).
var ErrSignatureRequired = errors.New("slsa: statement is not signed or signature did not verify")

// ErrSignatureUnverified is returned by VerifySignatures — whether or
// not signatures are required — when the statement's signature was
// checked and did not verify: unsigned means no claim of integrity,
// refuted means a claim of integrity that is false.
var ErrSignatureUnverified = errors.New("slsa: statement signature did not verify")

// ErrIdentityMismatch is returned by CheckIdentities when the statement
// is signed and verified but no expected signer matches the verified
// identities.
var ErrIdentityMismatch = errors.New("slsa: verified signer does not match any expected --signer")

// VerifierImplementation is the contract Verifier delegates to. It maps
// the verification layers described in the project design (signature,
// identity, predicate routing, control selection, control evaluation,
// result computation) onto discrete, independently testable methods.
//
// A counterfeiter-generated fake of this interface lives in the
// slsafakes sub-package and is injected via WithImplementation.
//
//counterfeiter:generate . VerifierImplementation
type VerifierImplementation interface {
	// VerifySignatures verifies the integrity of the statement's envelope
	// (layer 1).
	VerifySignatures(ctx context.Context, opts *VerificationOptions, statement attestation.Statement) error

	// CheckIdentities matches the verified identities against the expected
	// signer identities (layer 2). Currently a placeholder; identity-match
	// flags will be added later.
	CheckIdentities(ctx context.Context, opts *VerificationOptions, statement attestation.Statement) error

	// CheckSubjects binds the statement to the artifacts the caller
	// holds: every opts.Subjects entry must match a statement subject.
	// Returns one match per expected subject, in order, so callers can
	// report each; an empty list when nothing was asked.
	CheckSubjects(ctx context.Context, opts *VerificationOptions, statement attestation.Statement) ([]subject.Match, error)

	// CheckBuilder binds the provenance's builder.id to the statement's
	// verified signer using the builder registry and reports the outcome
	// as a core control result; nil for statements without a builder.
	CheckBuilder(ctx context.Context, opts *VerificationOptions, registry *builders.Registry, statement attestation.Statement) (*ControlResult, error)

	// ResolveCategory selects which catalog category to apply by looking
	// up the statement's predicate-type track in the catalog (layer 3
	// split build vs source). Honours opts.ForceTrack when set.
	ResolveCategory(opts *VerificationOptions, catalog *controls.Catalog, statement attestation.Statement) (controls.Category, error)

	// SelectCoreControls chooses the core SLSA controls to evaluate from
	// the catalog given the resolved category (layer 4).
	SelectCoreControls(opts *VerificationOptions, catalog *controls.Catalog, category controls.Category) []*controls.Control

	// SelectBuildTypeControls chooses the custom buildType controls
	// applicable to the given statement (layer 5).
	SelectBuildTypeControls(opts *VerificationOptions, catalog *controls.Catalog, statement attestation.Statement) []*controls.Control

	// SelectUserControls returns the user-supplied controls (layer 6).
	SelectUserControls(opts *VerificationOptions) []*controls.Control

	// RunControls evaluates a list of controls against the statement and
	// returns one result per control.
	RunControls(ctx context.Context, opts *VerificationOptions, ctrls []*controls.Control, statement attestation.Statement) ([]*ControlResult, error)

	// ComputeResult condenses the per-layer outcomes into the final
	// verification result, including the SLSA level (layer 7).
	ComputeResult(opts *VerificationOptions, coreResults, buildTypeResults, userResults []*ControlResult) (*Result, error)
}

// defaultImplementation is the production VerifierImplementation.
// Predicate routing and control evaluation are wired to the
// registry and CEL evaluator in the eval package.
type defaultImplementation struct {
	evaluator *eval.Evaluator
}

// newDefaultImplementation constructs a defaultImplementation with a
// fresh CEL evaluator.
func newDefaultImplementation() (*defaultImplementation, error) {
	ev, err := eval.NewEvaluator()
	if err != nil {
		return nil, fmt.Errorf("building CEL evaluator: %w", err)
	}
	return &defaultImplementation{evaluator: ev}, nil
}

// VerifySignatures inspects the Verification record attached to the
// statement by the loader. If RequireSignatures is set in opts, the
// statement must carry a verified signature; otherwise the layer is a
// pass-through that allows both signed and unsigned input.
func (*defaultImplementation) VerifySignatures(_ context.Context, opts *VerificationOptions, statement attestation.Statement) error {
	// A signature that was checked and refuted always fails, required
	// or not.
	if refuted, reason := refutedSignature(statement); refuted {
		if reason != "" {
			return fmt.Errorf("%w: %s", ErrSignatureUnverified, reason)
		}
		return ErrSignatureUnverified
	}
	if !opts.RequireSignatures {
		return nil
	}
	v := statement.GetVerification()
	if v == nil || !v.GetVerified() {
		// Surface the reason the verification recorded, when there is
		// one: "could not reach the transparency log" reads very
		// differently from "signature did not verify".
		if sv, ok := v.(interface {
			GetSignature() *sapi.SignatureVerification
		}); ok && sv.GetSignature().GetError() != "" {
			return fmt.Errorf("%w: %s", ErrSignatureRequired, sv.GetSignature().GetError())
		}
		return ErrSignatureRequired
	}
	return nil
}

// refutedSignature reports whether the statement's recorded signature
// verification concluded FAILED, with the recorded reason.
func refutedSignature(statement attestation.Statement) (refuted bool, reason string) {
	sv, ok := statement.GetVerification().(interface {
		GetSignature() *sapi.SignatureVerification
	})
	if !ok || sv.GetSignature() == nil {
		return false, ""
	}
	if sv.GetSignature().GetStatus() != sapi.VerificationStatus_FAILED {
		return false, ""
	}
	return true, sv.GetSignature().GetError()
}

// CheckIdentities matches the verified signer identities recorded on the
// statement against the caller's ExpectedSigners list. With an empty
// list it is a no-op, preserving the previous behaviour. With one or
// more expected identities it requires the statement to carry a verified
// signature; an unsigned statement returns ErrSignatureRequired and a
// signed-but-non-matching statement returns ErrIdentityMismatch. These are
// OR'ed: any expected signer matching a verified identity passes.
func (*defaultImplementation) CheckIdentities(_ context.Context, opts *VerificationOptions, statement attestation.Statement) error {
	if len(opts.ExpectedSigners) == 0 {
		return nil
	}

	v := statement.GetVerification()
	if v == nil || !v.GetVerified() {
		return ErrSignatureRequired
	}

	// The collector attaches *signer/api/v1.Verification on signed
	// envelopes. Its MatchesIdentity expects a *sapi.Identity, which is
	// exactly what NewIdentityFromSpec produces.
	sigVer, ok := v.(*sapi.Verification)
	if !ok {
		return fmt.Errorf("verification record is %T, want *signer/api/v1.Verification", v)
	}
	sv := sigVer.GetSignature()
	if sv == nil {
		return ErrSignatureRequired
	}

	if slices.ContainsFunc(opts.ExpectedSigners, sv.MatchesIdentity) {
		return nil
	}
	return ErrIdentityMismatch
}

// CheckSubjects matches every expected subject against the statement's
// subjects. It never errors on a mismatch: the outcome is reported per
// subject and the caller turns it into the verdict.
func (*defaultImplementation) CheckSubjects(_ context.Context, opts *VerificationOptions, statement attestation.Statement) ([]subject.Match, error) {
	if opts == nil || len(opts.Subjects) == 0 {
		return nil, nil
	}
	if statement == nil {
		return nil, errors.New("statement is required to check subjects")
	}
	return subject.MatchAll(opts.Subjects, statement.GetSubjects(), subject.WithGitDigestAliases(!opts.NoGitDigestAliases)), nil
}

// ResolveCategory routes the statement to a catalog category. The track
// resolution honours opts.ForceTrack when set or otherwise the catalog
// must associate the predicate type with exactly one track. If it matches
// more the resolution errors with "track required". Within the track, the
// core category is selected by opts.SpecVersion to the newest catalog at
// or below the requested SLSA spec version (empty means latest).
func (*defaultImplementation) ResolveCategory(opts *VerificationOptions, catalog *controls.Catalog, stmt attestation.Statement) (controls.Category, error) {
	track, err := resolveTrack(opts, catalog, stmt)
	if err != nil {
		return "", err
	}
	spec := ""
	if opts != nil {
		spec = opts.SpecVersion
	}
	category, _, err := catalog.ResolveCore(track, spec)
	return category, err
}

func (*defaultImplementation) SelectCoreControls(_ *VerificationOptions, catalog *controls.Catalog, category controls.Category) []*controls.Control {
	return catalog.Get(category)
}

// SelectBuildTypeControls returns the catalog entries under
// track/buildType for the statement's resolved track. For source
// statements the looked-up category ("source/buildType") simply doesn't
// exist in the catalog, so the layer stays empty.
func (*defaultImplementation) SelectBuildTypeControls(opts *VerificationOptions, catalog *controls.Catalog, stmt attestation.Statement) []*controls.Control {
	track, err := resolveTrack(opts, catalog, stmt)
	if err != nil {
		return nil
	}
	return catalog.Get(controls.Category(string(track) + "/buildType"))
}

// resolveTrack picks the track to evaluate the statement against. With
// opts.ForceTrack set, the forced track must be one of the catalog's
// known tracks for the predicate type, else an error. With ForceTrack
// empty, the predicate type must be associated with exactly one track
// in the catalog. Predicates that apply to more than one track require
// disambiguation.
func resolveTrack(opts *VerificationOptions, catalog *controls.Catalog, stmt attestation.Statement) (controls.Track, error) {
	pt := string(stmt.GetPredicateType())
	tracks := catalog.TracksOf(pt)
	if len(tracks) == 0 {
		return "", fmt.Errorf("no controls registered for predicate type %q", pt)
	}
	if opts != nil && opts.ForceTrack != "" {
		for _, t := range tracks {
			if t == opts.ForceTrack {
				return t, nil
			}
		}
		return "", fmt.Errorf(
			"predicate type %q is not applicable to forced track %q (applicable tracks: %v)",
			pt, opts.ForceTrack, tracks,
		)
	}
	if len(tracks) > 1 {
		return "", fmt.Errorf(
			"predicate type %q is associated with multiple tracks %v: set --track to disambiguate",
			pt, tracks,
		)
	}
	return tracks[0], nil
}

func (*defaultImplementation) SelectUserControls(opts *VerificationOptions) []*controls.Control {
	return opts.UserControls
}

// RunControls evaluates every control in the input list and returns one
// ControlResult per control. Controls whose checks don't match the
// statement's predicateType/buildType produce a StatusSkipped result
// (rather than being dropped) so the caller can render a complete
// roster.
func (d *defaultImplementation) RunControls(_ context.Context, opts *VerificationOptions, ctrls []*controls.Control, statement attestation.Statement) ([]*ControlResult, error) {
	pt := string(statement.GetPredicateType())

	predicate, err := extractPredicate(statement)
	if err != nil {
		return nil, fmt.Errorf("extracting predicate from statement: %w", err)
	}
	subjects := convertSubjects(statement.GetSubjects())
	buildType := eval.BuildTypeOf(predicate)

	results := make([]*ControlResult, 0, len(ctrls))
	for _, c := range ctrls {
		results = append(results, d.evaluateControl(c, pt, buildType, predicate, subjects, opts.Params))
	}
	return results, nil
}

// evaluateControl runs the first check in the control whose predicateType
// matches pt and whose buildTypes filter (when set) matches the
// statement's buildType. Returns a result with StatusSkipped when no
// check applies, so the caller still sees the control on the roster.
func (d *defaultImplementation) evaluateControl(
	c *controls.Control,
	predicateType, buildType string,
	predicate proto.Message,
	subjects []*intoto.ResourceDescriptor,
	params map[string]any,
) *ControlResult {
	var match *controls.Check
	for i := range c.Checks {
		ck := &c.Checks[i]
		if ck.PredicateType != predicateType {
			continue
		}
		if len(ck.BuildTypes) > 0 && !slices.Contains(ck.BuildTypes, buildType) {
			continue
		}
		match = ck
		break
	}
	if match == nil {
		return &ControlResult{ID: c.ID, Title: c.Title, SLSALevel: c.SLSALevel, Status: StatusSkipped}
	}

	cr := &ControlResult{ID: c.ID, Title: c.Title, SLSALevel: c.SLSALevel}
	for _, p := range match.Parameters {
		if _, ok := params[p]; !ok {
			cr.Status = StatusError
			cr.Message = fmt.Sprintf("missing required param %q", p)
			return cr
		}
	}
	// Optional parameters gate the check rather than the run: without
	// them the expression can't be evaluated, but the caller chose not
	// to state that expectation, so the control is skipped.
	for _, p := range match.OptionalParameters {
		if _, ok := params[p]; !ok {
			cr.Status = StatusSkipped
			cr.Message = fmt.Sprintf("param %q not provided", p)
			return cr
		}
	}

	pass, err := d.evaluator.Evaluate(predicateType, match.Expression, predicate, subjects, params)
	switch {
	case err != nil:
		cr.Status = StatusError
		cr.Message = err.Error()
	case pass:
		cr.Status = StatusPass
	default:
		cr.Status = StatusFail
	}
	return cr
}

// ComputeResult rolls up the per-layer control results into the final
// verification result. Status is PASS only when no control failed or
// errored across all three layers; with opts.MinLevel set, core controls
// declared above the minimum level are informative and their failure
// only caps the computed level, while the computed level itself must
// reach the minimum or the run fails. The SLSA level is the highest
// consecutive level (1..4) for which every core control declaring that
// level passed; levels with no declared controls are skipped (treated as
// trivially achieved as long as the chain is unbroken).
func (*defaultImplementation) ComputeResult(opts *VerificationOptions, coreResults, buildTypeResults, userResults []*ControlResult) (*Result, error) {
	r := &Result{
		Status:           StatusPass,
		CoreResults:      coreResults,
		BuildTypeResults: buildTypeResults,
		UserResults:      userResults,
	}
	minLevel := 0
	if opts != nil {
		r.VerifierID = opts.VerifierID
		minLevel = opts.MinLevel
	}

	for _, cr := range coreResults {
		if cr.Status == StatusPass || cr.Status == StatusSkipped {
			continue
		}
		// Leveled core controls above the required minimum cap the
		// computed level instead of failing the verification.
		if minLevel > 0 && cr.SLSALevel > minLevel {
			continue
		}
		r.Status = StatusFail
		break
	}
	for _, layer := range [][]*ControlResult{buildTypeResults, userResults} {
		if r.Status == StatusFail {
			break
		}
		for _, cr := range layer {
			if cr.Status != StatusPass && cr.Status != StatusSkipped {
				r.Status = StatusFail
				break
			}
		}
	}

	r.SLSALevel = computeSLSALevel(coreResults)

	// Requiring a level means reaching it. Controls at the required
	// level that were skipped or never declared do not fail on their
	// own, so the computed level is the only thing that can tell.
	if minLevel > 0 && r.SLSALevel < minLevel {
		r.Status = StatusFail
		r.Message = fmt.Sprintf("SLSA level %d is below the required level %d", r.SLSALevel, minLevel)
	}
	return r, nil
}

const maxSLSALevel = 4

// computeSLSALevel returns the highest consecutive level (1..maxSLSALevel)
// for which every applicable core control declaring that level passed.
// Levels with no declared controls (or where every declared control
// was skipped) are passed through transparently and they dont raise
// or break the chain.
func computeSLSALevel(coreResults []*ControlResult) int {
	byLevel := map[int][]*ControlResult{}
	for _, cr := range coreResults {
		if cr.SLSALevel == 0 {
			continue
		}
		byLevel[cr.SLSALevel] = append(byLevel[cr.SLSALevel], cr)
	}

	maxLevel := 0
	for level := 1; level <= maxSLSALevel; level++ {
		crs, ok := byLevel[level]
		if !ok {
			continue
		}
		applicable := 0
		allPassed := true
		for _, cr := range crs {
			if cr.Status == StatusSkipped {
				continue
			}
			applicable++
			if cr.Status != StatusPass {
				allPassed = false
				break
			}
		}
		if applicable == 0 {
			continue
		}
		if !allPassed {
			break
		}
		maxLevel = level
	}
	return maxLevel
}

// extractPredicate returns the parsed proto message carried by the
// statement's predicate. The collector wiring is responsible for
// populating this field with one of the registered SLSA proto messages.
func extractPredicate(stmt attestation.Statement) (proto.Message, error) {
	p := stmt.GetPredicate()
	if p == nil {
		return nil, errors.New("statement has no predicate")
	}
	parsed := p.GetParsed()
	if parsed == nil {
		return nil, errors.New("predicate has no parsed payload")
	}
	msg, ok := parsed.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("predicate parsed payload is not a proto message (got %T)", parsed)
	}
	return msg, nil
}

// convertSubjects projects the attestation.Subject interface onto the
// concrete in-toto ResourceDescriptor type so CEL can iterate over it
// using the registered proto descriptor.
func convertSubjects(subs []attestation.Subject) []*intoto.ResourceDescriptor {
	out := make([]*intoto.ResourceDescriptor, len(subs))
	for i, s := range subs {
		out[i] = &intoto.ResourceDescriptor{
			Name:   s.GetName(),
			Uri:    s.GetUri(),
			Digest: s.GetDigest(),
		}
	}
	return out
}
