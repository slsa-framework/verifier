// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
	"fmt"
	"slices"

	sapi "github.com/carabiner-dev/signer/api/v1"

	"github.com/slsa-framework/verifier/pkg/slsa/builders"
	"github.com/slsa-framework/verifier/pkg/slsa/controls"
	"github.com/slsa-framework/verifier/pkg/subject"
)

// Options holds construction-time settings for a Verifier.
type Options struct {
	// Catalog is the set of controls available to the verifier. When nil,
	// the verifier loads the embedded catalog at construction time.
	Catalog *controls.Catalog

	// Builders is the registry binding builders to their signing
	// identities. When nil, the verifier loads the embedded registry at
	// construction time.
	Builders *builders.Registry
}

// DefaultOptions returns a zero-value Options struct used when no options
// are provided to New.
func DefaultOptions() Options {
	return Options{}
}

// Option is a functional option applied at Verifier construction time.
type Option func(*Verifier) error

// WithCatalog sets the control catalog the verifier will use, replacing
// the embedded one.
func WithCatalog(c *controls.Catalog) Option {
	return func(v *Verifier) error {
		v.Options.Catalog = c
		return nil
	}
}

// WithBuilders sets the builder registry the verifier will use,
// replacing the embedded one.
func WithBuilders(r *builders.Registry) Option {
	return func(v *Verifier) error {
		v.Options.Builders = r
		return nil
	}
}

// WithImplementation overrides the verifier implementation. Primarily
// used in tests to inject a counterfeiter-generated fake.
func WithImplementation(impl VerifierImplementation) Option {
	return func(v *Verifier) error {
		v.impl = impl
		return nil
	}
}

// WithDefaultVerificationOptions sets the verification options that apply
// to every Verify call unless overridden by the iptions.
func WithDefaultVerificationOptions(o *VerificationOptions) Option {
	return func(v *Verifier) error {
		if o != nil {
			v.defaultVerificationOptions = *o
		}
		return nil
	}
}

// VerificationOptions holds per-call settings for Verifier.Verify.
type VerificationOptions struct {
	// RunBuildTypeControls toggles execution of custom buildType controls.
	RunBuildTypeControls bool

	// RunUserControls toggles execution of user supplied controls.
	RunUserControls bool

	// SkipBuildTypeChecks skips buildType controls whose parameters were
	// not set instead of failing the run with ErrBuildTypeParamsUnset.
	// BuildType controls that take no parameters still run.
	SkipBuildTypeChecks bool

	// RequireSignatures, when true, fails verification if the statement
	// does not carry a verified signature (ie loaded as a plain in-toto envelope
	// or failed to verify).
	RequireSignatures bool

	// UserControls is the list of user-supplied controls evaluated when
	// RunUserControls is true.
	UserControls []*controls.Control

	// ExpectedSigners is the set of identities alloed to sign the statement.
	// When set, CheckIdentities will only accept the statement if at
	// least one verified signer matches one of these (OR'ed). An empty list
	// is the default and skips identity matching.
	ExpectedSigners []*sapi.Identity

	// Subjects are the artifacts the caller holds and expects the
	// statement to be about. When non-empty, every one of them must
	// match a subject of the statement or the verification fails. Empty
	// (the default) binds the statement to nothing: it is verified on
	// its content alone.
	Subjects []*subject.Expected

	// NoGitDigestAliases requires exact digest algorithm names when
	// matching Subjects. By default git object digests (gitCommit,
	// gitTree, …) are interchangeable with the sha1 or sha256 hash they
	// are. See subject.WithGitDigestAliases.
	NoGitDigestAliases bool

	// ForceTrack overrides the catalog's predicate-type to track
	// resolution. Empty means "auto" (the catalog must associate the
	// predicate type with exactly one track). When set to a track
	// constant (TrackBuild/TrackSource), the verifier evaluates
	// against that track and errors if the catalog does not classify the
	// predicate type under it.
	ForceTrack controls.Track

	// Params is the parameter map exposed to CEL expressions as `params`.
	// Values are typically string or []string, matching what the --param
	// CLI flag produces.
	Params map[string]any

	// VerifierID identifies the entity performing the verification. It is
	// recorded on the Result and surfaces as verifier.id when a VSA is
	// emitted from the outcome. The CLI sets it from --verifier-id,
	// defaulting to the SLSA verifier project URL; applications embedding
	// the verifier should set their own identity. Empty by default.
	VerifierID string

	// SpecVersion selects the SLSA spec version whose verification
	// criteria (control catalog) the statement is evaluated against,
	// eg "1.2". Criteria carry forward across releases, so the newest
	// catalog at or below the requested version applies. Empty (the
	// default) means the latest version the catalog defines for the
	// resolved track.
	SpecVersion string

	// MinLevel is the SLSA level the attestation is required to reach.
	// When set (> 0), the run fails unless the computed level reaches
	// it, and core controls declared above it are informative: their
	// failure caps the computed level but does not fail the run. Zero
	// (the default) keeps the strict semantics where every applicable
	// control must pass. Controls without a declared level, buildType
	// controls and user controls are always required.
	MinLevel int

	// BuilderLevels are the highest SLSA build levels the caller trusts
	// builders to reach, keyed by builder id like the trusted_builders
	// parameter: an id without an @ also matches the builder at any ref.
	// The controls only see what the provenance records, not how
	// isolated its builder is or who generated the provenance, so the
	// computed level of provenance by one of these builders is capped at
	// its level. MinLevel is checked before the cap. Builders without an
	// entry are not capped. The builder id is what the provenance claims,
	// so a level only holds when the id is bound to the signer of its
	// builder (see the builder registry): otherwise any trusted signer can
	// claim the id of a builder with a higher level.
	BuilderLevels map[string]int
}

// DefaultVerificationOptions returns the default per-call options.
func DefaultVerificationOptions() VerificationOptions {
	return VerificationOptions{
		RunBuildTypeControls: true,
		RunUserControls:      true,
		Params:               map[string]any{},
	}
}

// VerificationOption is a functional option applied to a Verify call.
type VerificationOption func(*VerificationOptions) error

// WithBuildTypeControls toggles evaluation of custom buildType controls.
func WithBuildTypeControls(enabled bool) VerificationOption {
	return func(o *VerificationOptions) error {
		o.RunBuildTypeControls = enabled
		return nil
	}
}

// WithSkipBuildTypeChecks skips buildType controls whose parameters were
// not set, reporting them as skipped, instead of returning
// ErrBuildTypeParamsUnset when the caller set none of the parameters
// the catalog's checks for the statement's buildType accept.
func WithSkipBuildTypeChecks(skip bool) VerificationOption {
	return func(o *VerificationOptions) error {
		o.SkipBuildTypeChecks = skip
		return nil
	}
}

// WithUserControls toggles evaluation of user-supplied controls.
func WithUserControls(enabled bool) VerificationOption {
	return func(o *VerificationOptions) error {
		o.RunUserControls = enabled
		return nil
	}
}

// WithRequireSignatures toggles whether the verifier fails when the
// statement is unsigned or its signature did not verify.
func WithRequireSignatures(required bool) VerificationOption {
	return func(o *VerificationOptions) error {
		o.RequireSignatures = required
		return nil
	}
}

// WithExpectedSigner appends an expected signer identity. Calling this
// option multiple times accumulates entries (OR 'ed).
func WithExpectedSigner(id *sapi.Identity) VerificationOption {
	return func(o *VerificationOptions) error {
		if id == nil {
			return nil
		}
		o.ExpectedSigners = append(o.ExpectedSigners, id)
		return nil
	}
}

// WithExpectedSigners replaces the expected signer list with ids.
func WithExpectedSigners(ids []*sapi.Identity) VerificationOption {
	return func(o *VerificationOptions) error {
		o.ExpectedSigners = ids
		return nil
	}
}

// WithSubjects sets the artifacts the statement must be about: each one
// must match a statement subject (sharing at least one digest algorithm
// and agreeing on every shared one) or the verification fails. The
// list replaces any previous one; nil clears it.
func WithSubjects(expected []*subject.Expected) VerificationOption {
	return func(o *VerificationOptions) error {
		o.Subjects = slices.Clone(expected)
		return nil
	}
}

// WithGitDigestAliases controls whether an expected sha1 or sha256
// digest matches a statement subject carrying it as a git object digest,
// and the other way around. On by default; pass false to require the
// exact algorithm names.
func WithGitDigestAliases(enabled bool) VerificationOption {
	return func(o *VerificationOptions) error {
		o.NoGitDigestAliases = !enabled
		return nil
	}
}

// WithTrack forces the verifier to evaluate the statement against the
// given track regardless of how the catalog classifies the predicate
// type. The empty value means "auto" and falls back to catalog-driven
// resolution. Pass controls.TrackBuild or controls.TrackSource (or any
// future track) explicitly.
func WithTrack(track controls.Track) VerificationOption {
	return func(o *VerificationOptions) error {
		o.ForceTrack = track
		return nil
	}
}

// WithUserControlList sets the list of user-supplied controls to evaluate.
func WithUserControlList(list []*controls.Control) VerificationOption {
	return func(o *VerificationOptions) error {
		o.UserControls = list
		return nil
	}
}

// WithParam sets a single parameter on the params map exposed to CEL.
// Calling WithParam multiple times accumulates entries.
func WithParam(name string, value any) VerificationOption {
	return func(o *VerificationOptions) error {
		if o.Params == nil {
			o.Params = map[string]any{}
		}
		o.Params[name] = value
		return nil
	}
}

// WithParams replaces the params map with the provided one.
func WithParams(params map[string]any) VerificationOption {
	return func(o *VerificationOptions) error {
		o.Params = params
		return nil
	}
}

// WithSpecVersion selects the SLSA spec version whose verification
// criteria the statement is evaluated against (e.g. "1.2" or "v1.2").
// The newest catalog at or below the requested version applies. An
// empty string (default) selects the latest available.
func WithSpecVersion(version string) VerificationOption {
	return func(o *VerificationOptions) error {
		o.SpecVersion = version
		return nil
	}
}

// WithMinLevel sets the SLSA level the attestation must reach for the
// verification to pass: a computed level below it fails the run. Core
// controls declared above the minimum level become informative: when
// they fail they cap the computed SLSA level without failing the run.
// Zero (the default) requires every applicable control to pass
// regardless of level.
func WithMinLevel(level int) VerificationOption {
	return func(o *VerificationOptions) error {
		o.MinLevel = level
		return nil
	}
}

// WithBuilderLevels sets the highest SLSA build level the caller trusts
// each builder to reach, see VerificationOptions.BuilderLevels. A builder
// whose builds generate and sign their own provenance, for example, can
// record every field the level 3 controls check, yet reaches level 1
// only. WithMinLevel still selects the controls that must pass, so a
// level 1 builder can be held to the level 2 trusted builder check. The
// levels only hold for builder ids bound to their signers.
func WithBuilderLevels(levels map[string]int) VerificationOption {
	return func(o *VerificationOptions) error {
		for id, level := range levels {
			if id == "" || level < 1 || level > maxSLSALevel {
				return fmt.Errorf("builder level %d of %q: builders need an id and a level from 1 to %d", level, id, maxSLSALevel)
			}
		}
		o.BuilderLevels = levels
		return nil
	}
}

// WithVerifierID sets the identity of the entity performing the
// verification. It is recorded on the Result and used as verifier.id when
// a VSA is emitted. Consumer applications embedding the verifier should
// set their own identity here, the CLI sets the slsa-verifier project URL.
func WithVerifierID(id string) VerificationOption {
	return func(o *VerificationOptions) error {
		o.VerifierID = id
		return nil
	}
}
