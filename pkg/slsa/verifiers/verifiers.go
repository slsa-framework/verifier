// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

// Package verifiers holds the registry of VSA issuers the verifier can
// bind to their signing identity: for each known verifier.id, who must
// have signed the VSA for the id to count as proven rather than merely
// claimed. It is the counterpart of the builder registry for the
// verifier named in a Verification Summary Attestation.
package verifiers

import (
	"errors"
	"fmt"
	"strings"

	sapi "github.com/policylabs/signer/api/v1"

	"github.com/slsa-framework/verifier/pkg/slsa/builders"
)

// Verifier describes a VSA issuer and the identity that signs the VSAs
// it issues.
type Verifier struct {
	// ID is the verifier id as VSAs record it in verifier.id.
	ID string `yaml:"id"`
	// IDMatch is how ID is compared with verifier.id; exact by default.
	IDMatch builders.IDMatch `yaml:"idMatch,omitempty"`
	// Title names the verifier for people.
	Title string `yaml:"title,omitempty"`
	// Description explains what the verifier is and how it is bound.
	Description string `yaml:"description,omitempty"`
	// Issuer is the OIDC issuer of the verifier's signing certificate.
	// With Signer unset, the signer identity is derived from it and
	// ID: a sigstore identity from Issuer whose subject starts with
	// ID followed by a slash — any workflow of the repository the id
	// names, for verifiers whose id is their repository URL.
	Issuer string `yaml:"issuer,omitempty"`
	// Signer is the identity spec (see sapi.NewIdentityFromSpec) the
	// VSA must be signed by, when it cannot be derived from Issuer and
	// ID. Naming the exact workflow is the stronger binding.
	Signer string `yaml:"signer,omitempty"`
	// Ref constrains the ref carried by the signer identity; any by
	// default.
	Ref builders.RefPolicy `yaml:"ref,omitempty"`

	identity *sapi.Identity
}

// Validate checks the entry is complete and its signer identity parses.
func (v *Verifier) Validate() error {
	if v == nil {
		return errors.New("verifier is nil")
	}
	if strings.TrimSpace(v.ID) == "" {
		return errors.New("verifier has an empty id")
	}
	switch v.IDMatch {
	case "", builders.IDMatchExact, builders.IDMatchPrefix:
	default:
		return fmt.Errorf("verifier %q: idMatch must be %q or %q (got %q)", v.ID, builders.IDMatchExact, builders.IDMatchPrefix, v.IDMatch)
	}
	switch v.Ref {
	case "", builders.RefAny, builders.RefSemverTag:
	default:
		return fmt.Errorf("verifier %q: ref must be %q or %q (got %q)", v.ID, builders.RefAny, builders.RefSemverTag, v.Ref)
	}
	if v.Signer == "" && v.Issuer == "" {
		return fmt.Errorf("verifier %q: set signer or issuer", v.ID)
	}
	id, err := sapi.NewIdentityFromSpec(v.SignerSpec())
	if err != nil {
		return fmt.Errorf("verifier %q: signer identity: %w", v.ID, err)
	}
	v.identity = id
	return nil
}

// SignerSpec returns the identity spec the verifier's VSAs must be
// signed by: Signer when set, else one derived from Issuer and ID.
func (v *Verifier) SignerSpec() string {
	if v.Signer != "" {
		return v.Signer
	}
	subject := strings.TrimSuffix(v.ID, "/")
	if v.IDMatch != builders.IDMatchPrefix {
		subject += "/"
	}
	return "sigstore(identityMatch=prefix)::" + v.Issuer + "::" + subject
}

// Identity returns the parsed signer identity. Nil before Validate.
func (v *Verifier) Identity() *sapi.Identity {
	if v == nil {
		return nil
	}
	return v.identity
}

// MatchesID reports whether verifierID names this verifier.
func (v *Verifier) MatchesID(verifierID string) bool {
	if v.IDMatch == builders.IDMatchPrefix {
		return strings.HasPrefix(verifierID, v.ID)
	}
	return verifierID == v.ID
}

// MatchesSigner reports whether signer, an identity recorded on a
// verified signature, is this verifier's signer.
func (v *Verifier) MatchesSigner(signer *sapi.Identity) bool {
	if v == nil || v.identity == nil || signer == nil {
		return false
	}
	return (&sapi.SignatureVerification{Identities: []*sapi.Identity{signer}}).MatchesIdentity(v.identity)
}

// AllowsSigner reports whether signer is this verifier's signer at a
// ref its policy allows.
func (v *Verifier) AllowsSigner(signer *sapi.Identity) bool {
	if !v.MatchesSigner(signer) {
		return false
	}
	_, ref := builders.SplitRef(signerSubject(signer))
	return v.Ref.Allows(ref)
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

// Registry is an ordered set of verifiers. Exact-id entries take
// precedence over prefix entries in lookups.
type Registry struct {
	verifiers []*Verifier
}

// New returns a registry holding the given verifiers, validated. A
// later entry with the same id and idMatch replaces an earlier one.
func New(verifiers ...*Verifier) (*Registry, error) {
	r := &Registry{}
	for _, v := range verifiers {
		if err := r.Add(v); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Add validates v and adds it to the registry, replacing an entry with
// the same id and idMatch.
func (r *Registry) Add(v *Verifier) error {
	if err := v.Validate(); err != nil {
		return err
	}
	for i, existing := range r.verifiers {
		if existing.ID == v.ID && existing.IDMatch == v.IDMatch {
			r.verifiers[i] = v
			return nil
		}
	}
	r.verifiers = append(r.verifiers, v)
	return nil
}

// Merge adds every verifier of other into r, with other's entries
// replacing r's on the same id.
func (r *Registry) Merge(other *Registry) error {
	if other == nil {
		return nil
	}
	for _, v := range other.verifiers {
		if err := r.Add(v); err != nil {
			return err
		}
	}
	return nil
}

// Verifiers returns the entries, exact ids first.
func (r *Registry) Verifiers() []*Verifier {
	if r == nil {
		return nil
	}
	out := make([]*Verifier, 0, len(r.verifiers))
	for _, v := range r.verifiers {
		if v.IDMatch != builders.IDMatchPrefix {
			out = append(out, v)
		}
	}
	for _, v := range r.verifiers {
		if v.IDMatch == builders.IDMatchPrefix {
			out = append(out, v)
		}
	}
	return out
}

// Len returns the number of entries.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.verifiers)
}

// Lookup returns the verifier that verifierID names, or nil when the
// registry does not know it.
func (r *Registry) Lookup(verifierID string) *Verifier {
	for _, v := range r.Verifiers() {
		if v.MatchesID(verifierID) {
			return v
		}
	}
	return nil
}
