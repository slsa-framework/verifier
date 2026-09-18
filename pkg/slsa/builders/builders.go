// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package builders holds the registry of build platforms the verifier can
// bind to their signing identity: for each known builder, who must have
// signed the provenance for its builder.id to count as proven rather
// than merely claimed.
package builders

import (
	"errors"
	"fmt"
	"strings"

	sapi "github.com/carabiner-dev/signer/api/v1"
	"golang.org/x/mod/semver"
)

// IDMatch says how a registry entry's id is compared with a provenance's
// builder.id (with its @ref removed).
type IDMatch string

const (
	// IDMatchExact requires builder.id to be the entry's id.
	IDMatchExact IDMatch = "exact"
	// IDMatchPrefix accepts any builder.id starting with the entry's id,
	// for platforms where the builder is the workflow that ran and its
	// identity is what the certificate names.
	IDMatchPrefix IDMatch = "prefix"
)

// RefPolicy constrains the ref a signer identity carries after its @
// (https://github.com/org/repo/.github/workflows/build.yml@refs/tags/v1.2.3).
type RefPolicy string

const (
	// RefAny accepts any ref, including none.
	RefAny RefPolicy = "any"
	// RefSemverTag requires a release tag, refs/tags/vX.Y.Z: a builder
	// running from a branch or an arbitrary tag is not the released
	// builder its id names.
	RefSemverTag RefPolicy = "semver-tag"
)

// Allows reports whether ref satisfies the policy.
func (p RefPolicy) Allows(ref string) bool {
	switch p {
	case RefAny, "":
		return true
	case RefSemverTag:
		tag, ok := strings.CutPrefix(ref, "refs/tags/")
		if !ok || !semver.IsValid(tag) || semver.Build(tag) != "" {
			return false
		}
		core, _, _ := strings.Cut(tag, "-")
		return len(strings.Split(core, ".")) == 3
	default:
		return false
	}
}

// Builder describes a build platform and the identity that signs the
// provenance it produces.
type Builder struct {
	// ID is the builder id as provenance records it in builder.id, without
	// the @ref the GitHub builders append.
	ID string `yaml:"id"`
	// IDMatch is how ID is compared with builder.id; exact by default.
	IDMatch IDMatch `yaml:"idMatch,omitempty"`
	// Title names the builder for people.
	Title string `yaml:"title,omitempty"`
	// Description explains what the builder is and how it is bound.
	Description string `yaml:"description,omitempty"`
	// Issuer is the OIDC issuer of the builder's signing certificate. With
	// Signer unset, the signer identity is derived from it and ID: a
	// sigstore identity from Issuer whose subject starts with ID (the
	// builder's ref follows it after an @).
	Issuer string `yaml:"issuer,omitempty"`
	// Signer is the identity spec (see sapi.NewIdentityFromSpec) the
	// provenance must be signed by, when it cannot be derived from
	// Issuer and ID.
	Signer string `yaml:"signer,omitempty"`
	// Ref constrains the ref carried by the signer identity; any by
	// default.
	Ref RefPolicy `yaml:"ref,omitempty"`
	// Delegated marks a builder that runs other builders: its certificate
	// proves the delegator ran, while builder.id names the delegated
	// builder, which is not expected to equal the signer identity.
	Delegated bool `yaml:"delegated,omitempty"`
	// Observer marks a watcher that attests runs it observed: its
	// certificate proves the observer ran, and builder.id must name the
	// workflow the certificate's build config URI says the observer ran
	// for, which proves that workflow really ran.
	Observer bool `yaml:"observer,omitempty"`
	// SourceRepositoryBound asserts the signing certificate's source
	// repository is the repository the artifact was built from, so it
	// can be compared with the expected source.
	SourceRepositoryBound bool `yaml:"sourceRepositoryBound,omitempty"`

	identity *sapi.Identity
}

// Validate checks the entry is complete and its signer identity parses.
func (b *Builder) Validate() error {
	if b == nil {
		return errors.New("builder is nil")
	}
	if strings.TrimSpace(b.ID) == "" {
		return errors.New("builder has an empty id")
	}
	if strings.Contains(b.ID, "@") {
		return fmt.Errorf("builder %q: id must not carry a ref (@...)", b.ID)
	}
	switch b.IDMatch {
	case "", IDMatchExact, IDMatchPrefix:
	default:
		return fmt.Errorf("builder %q: idMatch must be %q or %q (got %q)", b.ID, IDMatchExact, IDMatchPrefix, b.IDMatch)
	}
	switch b.Ref {
	case "", RefAny, RefSemverTag:
	default:
		return fmt.Errorf("builder %q: ref must be %q or %q (got %q)", b.ID, RefAny, RefSemverTag, b.Ref)
	}
	if b.Signer == "" && b.Issuer == "" {
		return fmt.Errorf("builder %q: set signer or issuer", b.ID)
	}
	if b.Observer && b.Delegated {
		return fmt.Errorf("builder %q: observer and delegated are mutually exclusive", b.ID)
	}
	if b.Observer && b.IDMatch == IDMatchPrefix {
		return fmt.Errorf("builder %q: an observer entry names its signer workflow exactly; prefix ids are not supported", b.ID)
	}
	id, err := sapi.NewIdentityFromSpec(b.SignerSpec())
	if err != nil {
		return fmt.Errorf("builder %q: signer identity: %w", b.ID, err)
	}
	b.identity = id
	return nil
}

// SignerSpec returns the identity spec the builder's provenance must be
// signed by: Signer when set, else one derived from Issuer and ID.
func (b *Builder) SignerSpec() string {
	if b.Signer != "" {
		return b.Signer
	}
	subject := b.ID
	if b.IDMatch != IDMatchPrefix {
		subject += "@"
	}
	return "sigstore(identityMatch=prefix)::" + b.Issuer + "::" + subject
}

// Identity returns the parsed signer identity. Nil before Validate.
func (b *Builder) Identity() *sapi.Identity {
	if b == nil {
		return nil
	}
	return b.identity
}

// MatchesID reports whether builderID (its @ref ignored) names this
// builder.
func (b *Builder) MatchesID(builderID string) bool {
	base, _ := SplitRef(builderID)
	if b.IDMatch == IDMatchPrefix {
		return strings.HasPrefix(base, b.ID)
	}
	return base == b.ID
}

// MatchesSigner reports whether signer, an identity recorded on a
// verified signature, is this builder's signer.
func (b *Builder) MatchesSigner(signer *sapi.Identity) bool {
	if b == nil || b.identity == nil || signer == nil {
		return false
	}
	// The signer library matches expectations against a verification's
	// identities as a set; wrap the single identity as one.
	return (&sapi.SignatureVerification{Identities: []*sapi.Identity{signer}}).MatchesIdentity(b.identity)
}

// SplitRef separates a builder id or signer subject from the ref it
// carries after the first @, if any.
func SplitRef(id string) (base, ref string) {
	base, ref, _ = strings.Cut(id, "@")
	return base, ref
}

// Registry is an ordered set of builders. Exact-id entries take
// precedence over prefix entries in lookups, so a specific builder can
// be described alongside the platform pattern that would also match it.
type Registry struct {
	builders []*Builder
}

// New returns a registry holding the given builders, validated. A later
// entry with the same id and idMatch replaces an earlier one, so
// user-supplied entries override the embedded ones.
func New(builders ...*Builder) (*Registry, error) {
	r := &Registry{}
	for _, b := range builders {
		if err := r.Add(b); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Add validates b and adds it to the registry, replacing an entry with
// the same id and idMatch.
func (r *Registry) Add(b *Builder) error {
	if err := b.Validate(); err != nil {
		return err
	}
	for i, existing := range r.builders {
		if existing.ID == b.ID && existing.IDMatch == b.IDMatch {
			r.builders[i] = b
			return nil
		}
	}
	r.builders = append(r.builders, b)
	return nil
}

// Merge adds every builder of other into r, with other's entries
// replacing r's on the same id.
func (r *Registry) Merge(other *Registry) error {
	if other == nil {
		return nil
	}
	for _, b := range other.builders {
		if err := r.Add(b); err != nil {
			return err
		}
	}
	return nil
}

// Builders returns the entries, exact ids first.
func (r *Registry) Builders() []*Builder {
	if r == nil {
		return nil
	}
	out := make([]*Builder, 0, len(r.builders))
	for _, b := range r.builders {
		if b.IDMatch != IDMatchPrefix {
			out = append(out, b)
		}
	}
	for _, b := range r.builders {
		if b.IDMatch == IDMatchPrefix {
			out = append(out, b)
		}
	}
	return out
}

// Len returns the number of entries.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.builders)
}

// Lookup returns the builder that builderID names, or nil when the
// registry does not know it.
func (r *Registry) Lookup(builderID string) *Builder {
	for _, b := range r.Builders() {
		if b.MatchesID(builderID) {
			return b
		}
	}
	return nil
}

// ForSigner returns the builder whose signer identity signer is, or nil
// when no known builder signs with it.
func (r *Registry) ForSigner(signer *sapi.Identity) *Builder {
	for _, b := range r.Builders() {
		if b.MatchesSigner(signer) {
			return b
		}
	}
	return nil
}

// ParseBinding parses a builder given on the command line as
// "id=signer-spec" or "id=issuer": the value is an identity spec when
// it has a spec's shape (type(...)::..., spiffe://..., ref:...) and an
// OIDC issuer otherwise. The binding is exact on id, accepts any ref
// and, having no way to know, does not bind the source repository.
func ParseBinding(s string) (*Builder, error) {
	id, value, ok := strings.Cut(s, "=")
	id = strings.TrimSpace(id)
	value = strings.TrimSpace(value)
	if !ok || id == "" || value == "" {
		return nil, fmt.Errorf("builder binding %q: want id=signer-spec or id=issuer", s)
	}
	b := &Builder{ID: id}
	if isIdentitySpec(value) {
		b.Signer = value
	} else {
		b.Issuer = value
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return b, nil
}

// isIdentitySpec reports whether s has the shape of an identity spec
// rather than of an issuer URL.
func isIdentitySpec(s string) bool {
	return strings.Contains(s, "::") || strings.HasPrefix(s, "spiffe://") || strings.HasPrefix(s, "ref:")
}
