// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"context"
	"errors"
	"fmt"
	"strings"

	sapi "github.com/policylabs/signer/api/v1"

	"github.com/slsa-framework/verifier/pkg/slsa/verifiers"
	"github.com/slsa-framework/verifier/pkg/slsa/vsa"
	"github.com/slsa-framework/verifier/pkg/subject"
)

// ErrVerifierUnbound is returned by VerifyVSA when an accepted verifier
// has no authorized signer — neither its own nor a wildcard — and
// VSAOptions.AllowUnbound is false. A VSA's verifier.id is a claim
// written by whoever produced the document; without a signer bound to
// it, matching the id proves nothing about who issued the VSA.
var ErrVerifierUnbound = errors.New("verifier has no authorized signer")

// VerifierBinding names an accepted verifier and the signer identities
// authorized to issue VSAs on its behalf.
type VerifierBinding struct {
	// ID is matched exactly against VSA.Verifier.ID.
	ID string

	// Signers are identities allowed to sign VSAs from this verifier,
	// on top of any wildcard signers in VSAOptions.Signers. A verifier
	// with neither is unbound: see VSAOptions.AllowUnbound.
	Signers []*sapi.Identity
}

// VSAOptions configures the hardcoded checks VerifyVSA runs against
// an attestation's normalized VSA representation.
//
// Field semantics:
//   - Verifiers lists the accepted verifiers, OR-matched on ID against
//     VSA.Verifier.ID. At least one is required; a VSA with no
//     asserted verifier identity carries very weak trust value.
//   - Signers are wildcard identities authorized to sign for every
//     accepted verifier. A verifier's own Signers add to them.
//   - The signer check binds the matched verifier to who actually
//     signed the envelope: the envelope's verified signature must
//     match one of the identities authorized for that verifier. It
//     runs whenever the matched verifier has any authorized signer.
//   - Registry supplies the signer of an accepted verifier given
//     without one, when it knows the id, along with the ref policy
//     that signer must satisfy.
//   - AllowUnbound permits verifiers with no authorized signer at all,
//     in which case only the ID is matched. Off by default, VerifyVSA
//     returns ErrVerifierUnbound instead.
//   - Subjects are the artifacts the caller holds and expects the VSA
//     to be about. Every one must match a VSA subject (sharing at
//     least one digest algorithm and agreeing on every shared one) or
//     the result fails; each outcome is reported in VSAResult.Subjects.
//     Empty binds the VSA to nothing. By default a sha1 or sha256 digest
//     meets a git object digest of the same hash; NoGitDigestAliases
//     requires the exact algorithm names (see
//     subject.WithGitDigestAliases).
//   - Levels is OR-matched against VSA.VerifiedLevels — at least one
//     listed level must be satisfied. For canonical SLSA level
//     strings (e.g. SLSA_BUILD_LEVEL_3) the match is "at-or-above":
//     a VSA verifiedLevel of SLSA_BUILD_LEVEL_4 satisfies a want of
//     SLSA_BUILD_LEVEL_3 within the same track. Non-canonical
//     strings only match exactly. Skipped when empty.
//   - Resource and Policy are exact-match against ResourceURI and
//     Policy.URI respectively. Skipped when empty.
//   - Dependencies is AND-matched: every key must appear in
//     VSA.DependencyLevels (count values are not consulted).
//     Skipped when empty.
type VSAOptions struct {
	Verifiers    []VerifierBinding
	Signers      []*sapi.Identity
	AllowUnbound bool
	// Registry binds verifier ids to their signers, for accepted
	// verifiers given without one; see verifiers.Registry.
	Registry           *verifiers.Registry
	Subjects           []*subject.Expected
	NoGitDigestAliases bool
	Levels             []string
	Resource           string
	Policy             string
	Dependencies       []string
}

// binding returns the accepted verifier matching id, if any.
func (o *VSAOptions) binding(id string) (VerifierBinding, bool) {
	for _, b := range o.Verifiers {
		if b.ID == id {
			return b, true
		}
	}
	return VerifierBinding{}, false
}

// authorizedSigners returns the identities allowed to sign for b: its
// own, the registry's for its id when it has none of its own, plus the
// wildcard set.
func (o *VSAOptions) authorizedSigners(b VerifierBinding) []*sapi.Identity {
	ids := make([]*sapi.Identity, 0, len(b.Signers)+len(o.Signers)+1)
	ids = append(ids, b.Signers...)
	if entry := o.registered(b); entry != nil {
		ids = append(ids, entry.Identity())
	}
	return append(ids, o.Signers...)
}

// registered returns the registry entry binding b's id, when b has no
// signer of its own and the registry knows the id.
func (o *VSAOptions) registered(b VerifierBinding) *verifiers.Verifier {
	if len(b.Signers) > 0 || o.Registry == nil {
		return nil
	}
	return o.Registry.Lookup(b.ID)
}

// validate checks the options are usable before any parsing happens.
func (o *VSAOptions) validate() error {
	if len(o.Verifiers) == 0 {
		return errors.New("VSAOptions.Verifiers must name at least one verifier")
	}
	var unbound []string
	for _, b := range o.Verifiers {
		if b.ID == "" {
			return errors.New("VSAOptions.Verifiers contains a verifier with an empty ID")
		}
		if len(o.authorizedSigners(b)) == 0 {
			unbound = append(unbound, b.ID)
		}
	}
	if len(unbound) > 0 && !o.AllowUnbound {
		return fmt.Errorf("%w: %s", ErrVerifierUnbound, strings.Join(unbound, ", "))
	}
	return nil
}

// VSAResult is what VerifyVSA returns. VSA is the normalized
// version-neutral predicate; Checks is the per-check outcome in
// display order — exactly the entries needed to render a result
// table for the user.
type VSAResult struct {
	// VSA is the normalized VSA predicate parsed from the envelope.
	// Available to callers that want to display additional fields
	// (e.g. dependency-level counts) alongside the check results.
	VSA *vsa.VSA

	// Checks is the per-check outcome. Always includes the always-on
	// checks (result, verifier); optional checks appear when the
	// corresponding VSAOptions field is non-empty.
	Checks []VSACheck

	// Signers lists the principals of the envelope's verified signers,
	// when the envelope records them, for display alongside the
	// verifier it vouched for. Empty for unsigned or unverified
	// envelopes.
	Signers []string

	// Subjects holds the outcome of binding the VSA to the artifacts
	// the caller holds, one entry per VSAOptions.Subjects entry in
	// order. Empty when none were expected.
	Subjects []subject.Match
}

// Pass reports whether every check passed and every expected subject
// was found.
func (r *VSAResult) Pass() bool {
	for _, c := range r.Checks {
		if !c.Pass {
			return false
		}
	}
	return subject.AllMatched(r.Subjects)
}

// VSACheck is the result of one hardcoded VSA check.
type VSACheck struct {
	// Name is a human-readable description of what was checked
	// (e.g. `Verifier == "https://verify.example.com"`).
	Name string

	// Pass reports whether the check succeeded.
	Pass bool

	// Message is populated on failure with the observed value
	// (e.g. `verifier.id = "..."`). Empty when Pass is true.
	Message string
}

// VerifyVSA extracts the VSA predicate from env (which must already
// have been signature-verified by the caller — see VerifySignatures),
// converts it to the normalized representation via pkg/slsa/vsa, and
// runs the hardcoded checks selected by opts.
//
// Returns vsa.ErrNotVSA wrapped with the offending predicate type
// when env carries a non-VSA predicate, and ErrVerifierUnbound when
// an accepted verifier has no authorized signer and opts.AllowUnbound
// is false. Always-on checks (verificationResult == PASSED and the
// verifier match) always appear in the result; the signer check
// appears when the matched verifier has authorized signers, and the
// optional checks only when the corresponding VSAOptions field is
// set.
//
// ctx is accepted for future cancellation/deadline plumbing; the
// current check set is purely in-memory and ignores it.
func (*Verifier) VerifyVSA(_ context.Context, env Envelope, opts *VSAOptions) (*VSAResult, error) {
	if env == nil {
		return nil, errors.New("nil envelope")
	}
	if opts == nil {
		return nil, errors.New("nil VSAOptions")
	}
	if err := opts.validate(); err != nil {
		return nil, err
	}

	stmt := env.GetStatement()
	if stmt == nil {
		return nil, errors.New("envelope produced no statement")
	}
	v, err := vsa.FromStatement(stmt)
	if err != nil {
		if errors.Is(err, vsa.ErrNotVSA) {
			return nil, fmt.Errorf("%w (got %q)", err, stmt.GetPredicateType())
		}
		return nil, fmt.Errorf("extracting VSA: %w", err)
	}

	checks := []VSACheck{
		checkVSAResult(v),
		checkVSAVerifier(v, opts.Verifiers),
	}
	// Bind the verifier to who signed: only meaningful once the
	// claimed verifier is one we accept, and only when it has signers.
	if b, ok := opts.binding(v.Verifier.ID); ok {
		if allowed := opts.authorizedSigners(b); len(allowed) > 0 {
			checks = append(checks, checkVSASigner(env, b.ID, allowed, opts.registered(b)))
		}
	}
	if len(opts.Levels) > 0 {
		checks = append(checks, checkVSALevels(v, opts.Levels))
	}
	if opts.Resource != "" {
		checks = append(checks, checkVSAResource(v, opts.Resource))
	}
	if opts.Policy != "" {
		checks = append(checks, checkVSAPolicy(v, opts.Policy))
	}
	if len(opts.Dependencies) > 0 {
		checks = append(checks, checkVSADependencies(v, opts.Dependencies))
	}
	result := &VSAResult{VSA: v, Checks: checks, Signers: recordedSigners(env.GetVerification())}
	if len(opts.Subjects) > 0 {
		result.Subjects = subject.MatchAll(opts.Subjects, stmt.GetSubjects(), subject.WithGitDigestAliases(!opts.NoGitDigestAliases))
	}
	return result, nil
}

func checkVSAResult(v *vsa.VSA) VSACheck {
	c := VSACheck{Name: "Result is PASSED"}
	if v.Passed() {
		c.Pass = true
		return c
	}
	got := v.VerificationResult
	if got == "" {
		got = "(empty)"
	}
	c.Message = fmt.Sprintf("verificationResult = %s", got)
	return c
}

func checkVSAVerifier(v *vsa.VSA, accepted []VerifierBinding) VSACheck {
	ids := make([]string, 0, len(accepted))
	for _, b := range accepted {
		ids = append(ids, b.ID)
	}
	c := VSACheck{Name: fmt.Sprintf("Verifier == %q", ids[0])}
	if len(ids) > 1 {
		c.Name = fmt.Sprintf("Verifier is one of %q", ids)
	}
	for _, id := range ids {
		if v.Verifier.ID == id {
			c.Pass = true
			return c
		}
	}
	c.Message = fmt.Sprintf("verifier.id = %q", v.Verifier.ID)
	return c
}

// checkVSASigner binds the matched verifier to the envelope's signer:
// the envelope must carry a verified signature whose identity matches
// one of the signers authorized for that verifier.
func checkVSASigner(env Envelope, verifierID string, allowed []*sapi.Identity, entry *verifiers.Verifier) VSACheck {
	c := VSACheck{Name: fmt.Sprintf("Signer is authorized for verifier %q", verifierID)}
	ver := env.GetVerification()
	if ver == nil || !ver.GetVerified() {
		c.Message = "envelope carries no verified signature"
		return c
	}
	// The registry's signer is authorized only at a ref its policy
	// allows: the same workflow from a branch is not the verifier.
	var refMessage string
	for _, signer := range recordedIdentities(ver) {
		single := &sapi.SignatureVerification{Identities: []*sapi.Identity{signer}}
		for _, id := range allowed {
			if id == nil || !single.MatchesIdentity(id) {
				continue
			}
			if entry != nil && id == entry.Identity() && !entry.AllowsSigner(signer) {
				refMessage = fmt.Sprintf("signed by %s at a ref the registry does not allow for this verifier", signer.Principal())
				continue
			}
			c.Pass = true
			return c
		}
	}
	if refMessage != "" {
		c.Message = refMessage
		return c
	}
	if signers := recordedSigners(ver); len(signers) > 0 {
		c.Message = fmt.Sprintf("signed by %q, not authorized for this verifier", signers)
		return c
	}
	c.Message = "verified signature matches none of the authorized signers"
	return c
}

// recordedIdentities returns the identities an envelope's verification
// recorded for its verified signature, when it exposes them.
func recordedIdentities(ver interface{ GetVerified() bool }) []*sapi.Identity {
	sv, ok := ver.(interface {
		GetSignature() *sapi.SignatureVerification
	})
	if !ok || sv.GetSignature() == nil || !sv.GetSignature().GetVerified() {
		return nil
	}
	return sv.GetSignature().GetIdentities()
}

// recordedSigners lists the principals of the identities an envelope's
// verification recorded, when it exposes them.
func recordedSigners(ver interface{ GetVerified() bool }) []string {
	sv, ok := ver.(interface {
		GetSignature() *sapi.SignatureVerification
	})
	if !ok || sv.GetSignature() == nil || !sv.GetSignature().GetVerified() {
		return nil
	}
	var out []string
	for _, id := range sv.GetSignature().GetIdentities() {
		out = append(out, id.Principal())
	}
	return out
}

// checkVSALevels OR-matches the VSA's verifiedLevels against want.
// For canonical SLSA level strings the comparison is at-or-above
// within the same track (see matchesLevel); freeform strings only
// match exactly.
func checkVSALevels(v *vsa.VSA, want []string) VSACheck {
	c := VSACheck{Name: fmt.Sprintf("verifiedLevels satisfies one of %v (or higher per track)", want)}
	for _, w := range want {
		for _, observed := range v.VerifiedLevels {
			if matchesLevel(w, observed) {
				c.Pass = true
				return c
			}
		}
	}
	c.Message = fmt.Sprintf("verifiedLevels = %v", v.VerifiedLevels)
	return c
}

func checkVSAResource(v *vsa.VSA, want string) VSACheck {
	c := VSACheck{Name: fmt.Sprintf("resourceUri == %q", want)}
	if v.ResourceURI == want {
		c.Pass = true
		return c
	}
	c.Message = fmt.Sprintf("resourceUri = %q", v.ResourceURI)
	return c
}

func checkVSAPolicy(v *vsa.VSA, want string) VSACheck {
	c := VSACheck{Name: fmt.Sprintf("policy.uri == %q", want)}
	if v.Policy.URI == want {
		c.Pass = true
		return c
	}
	c.Message = fmt.Sprintf("policy.uri = %q", v.Policy.URI)
	return c
}

// checkVSADependencies enforces that every key in want appears in
// the VSA's dependencyLevels map. Count values are not consulted —
// presence alone is the check. Missing keys are listed in the
// failure message alongside the keys the VSA does report.
func checkVSADependencies(v *vsa.VSA, want []string) VSACheck {
	c := VSACheck{Name: fmt.Sprintf("dependencyLevels contains all of %v", want)}
	var missing []string
	for _, w := range want {
		if _, ok := v.DependencyLevels[w]; !ok {
			missing = append(missing, w)
		}
	}
	if len(missing) == 0 {
		c.Pass = true
		return c
	}
	keys := make([]string, 0, len(v.DependencyLevels))
	for k := range v.DependencyLevels {
		keys = append(keys, k)
	}
	c.Message = fmt.Sprintf("missing %v (have %v)", missing, keys)
	return c
}
