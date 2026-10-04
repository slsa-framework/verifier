// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/slsa-framework/verifier/pkg/subject"
)

// ErrNoApplicableAttestation is returned by Select when none of the
// envelopes in a file is one the caller can verify.
var ErrNoApplicableAttestation = errors.New("no applicable attestation")

// ErrAmbiguousAttestation is returned by Select when several envelopes
// in a file could be the one to verify and nothing tells them apart.
var ErrAmbiguousAttestation = errors.New("ambiguous attestation")

// Selection says which of the attestations in a file a verification is
// about. Files often hold several: a commit's git note accumulates the
// source provenance, tag provenance and VSAs sourcetool pushes, and a
// release's attestations file may carry provenance next to other
// attestations.
type Selection struct {
	// Kind names what is being looked for, for messages ("build
	// provenance", "VSA").
	Kind string

	// PredicateTypes are the predicate types the caller verifies. Empty
	// accepts any.
	PredicateTypes []string

	// Subjects, when given, must all be subjects of the attestation.
	Subjects []*subject.Expected

	// NoGitDigestAliases matches subject digests by exact algorithm
	// name; see subject.WithGitDigestAliases.
	NoGitDigestAliases bool

	// Prefer breaks a tie among candidates of different predicate
	// types: the first type listed that any candidate has wins.
	Prefer []string
}

// Select picks the envelope a verification is about. A single envelope
// is returned as is, whatever it holds: the verification itself will
// say whether it applies. Among several, those of the selection's
// predicate types about its subjects remain; a preference breaks a tie
// between types, and what is left must be exactly one.
func Select(envs []Envelope, sel *Selection) (Envelope, error) {
	if sel == nil {
		sel = &Selection{}
	}
	kind := sel.Kind
	if kind == "" {
		kind = "attestation"
	}
	switch len(envs) {
	case 0:
		return nil, fmt.Errorf("%w: no %s to select from", ErrNoApplicableAttestation, kind)
	case 1:
		return envs[0], nil
	}

	candidates := make([]Envelope, 0, len(envs))
	seen := map[string]bool{}
	for _, env := range envs {
		stmt := env.GetStatement()
		if stmt == nil {
			continue
		}
		// A note can hold the same bundle twice when two steps stored
		// it: an exact duplicate is one attestation, not two.
		if key := envelopeKey(env); seen[key] {
			continue
		} else {
			seen[key] = true
		}
		if len(sel.PredicateTypes) > 0 && !slices.Contains(sel.PredicateTypes, string(stmt.GetPredicateType())) {
			continue
		}
		if len(sel.Subjects) > 0 {
			matches := subject.MatchAll(sel.Subjects, stmt.GetSubjects(), subject.WithGitDigestAliases(!sel.NoGitDigestAliases))
			if !subject.AllMatched(matches) {
				continue
			}
		}
		candidates = append(candidates, env)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("%w: none of the %d attestations in the file is a %s%s (found %s)",
			ErrNoApplicableAttestation, len(envs), kind, aboutSubjects(sel.Subjects), describeTypes(envs))
	}
	if len(candidates) > 1 {
		for _, preferred := range sel.Prefer {
			var kept []Envelope
			for _, env := range candidates {
				if string(env.GetStatement().GetPredicateType()) == preferred {
					kept = append(kept, env)
				}
			}
			if len(kept) > 0 {
				candidates = kept
				break
			}
		}
	}
	if len(candidates) > 1 {
		return nil, fmt.Errorf("%w: %d of the %d attestations in the file are a %s%s (%s); name the subject or split the file",
			ErrAmbiguousAttestation, len(candidates), len(envs), kind, aboutSubjects(sel.Subjects), describeTypes(candidates))
	}
	return candidates[0], nil
}

// envelopeKey identifies an envelope by its predicate type, subjects,
// predicate data and signatures, so exact duplicates share a key.
func envelopeKey(env Envelope) string {
	stmt := env.GetStatement()
	var b strings.Builder
	b.WriteString(string(stmt.GetPredicateType()))
	for _, s := range stmt.GetSubjects() {
		digests := s.GetDigest()
		algos := make([]string, 0, len(digests))
		for algo := range digests {
			algos = append(algos, algo)
		}
		sort.Strings(algos)
		for _, algo := range algos {
			b.WriteString("|" + algo + "=" + digests[algo])
		}
		b.WriteString(";")
	}
	if pred := stmt.GetPredicate(); pred != nil {
		b.Write(pred.GetData())
	}
	for _, sig := range env.GetSignatures() {
		if s, ok := sig.(interface{ GetSig() []byte }); ok {
			b.Write(s.GetSig())
		} else {
			fmt.Fprintf(&b, "%#v", sig)
		}
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func aboutSubjects(subjects []*subject.Expected) string {
	if len(subjects) == 0 {
		return ""
	}
	return " about the given subject"
}

// describeTypes lists the predicate types of envs, deduplicated, with
// the count of each.
func describeTypes(envs []Envelope) string {
	counts := map[string]int{}
	var order []string
	for _, env := range envs {
		t := "no statement"
		if stmt := env.GetStatement(); stmt != nil {
			t = string(stmt.GetPredicateType())
		}
		if _, seen := counts[t]; !seen {
			order = append(order, t)
		}
		counts[t]++
	}
	parts := make([]string, 0, len(order))
	for _, t := range order {
		if counts[t] > 1 {
			parts = append(parts, fmt.Sprintf("%d × %s", counts[t], t))
		} else {
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, ", ")
}
