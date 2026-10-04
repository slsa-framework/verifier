// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package vsa

import (
	"errors"
	"fmt"

	"github.com/policylabs/attestation"
)

// ErrNotVSA is returned when a statement carries a predicate type
// that no registered Adapter handles.
var ErrNotVSA = errors.New("not a VSA predicate type")

// Adapter converts a parsed VSA predicate payload of a specific
// version into the normalized VSA representation. Implementations
// declare their predicate-type URI so the registry can dispatch by
// statement.predicateType.
//
// Convert takes `any` rather than proto.Message so individual versions
// can pick the wire-format path that fits — v1 round-trips cleanly
// through protojson, but v0.2 ships json_name overrides that conflict
// with the camelCase the SLSA spec actually uses, so it parses through
// encoding/json into a hand-rolled struct. Each adapter type-asserts
// its expected concrete type.
type Adapter interface {
	// PredicateType returns the URI this adapter handles, e.g.
	// "https://slsa.dev/verification_summary/v1".
	PredicateType() string

	// Convert maps parsed (the value the registered predicate parser
	// placed in the in-toto statement's Predicate.Parsed) into a *VSA.
	// Returns an error if parsed is not the type this adapter expects.
	Convert(parsed any) (*VSA, error)
}

// registry maps predicate-type URI to its Adapter. Populated by the
// init() functions in v0.go and v1.go.
var registry = map[string]Adapter{}

// register adds a to the registry. Called from per-version init().
// Duplicate registration panics — it indicates a programmer error.
func register(a Adapter) {
	pt := a.PredicateType()
	if _, dup := registry[pt]; dup {
		panic(fmt.Sprintf("vsa: duplicate adapter registration for %q", pt))
	}
	registry[pt] = a
}

// IsVSAPredicateType reports whether uri is a registered VSA
// predicate-type URI.
func IsVSAPredicateType(uri string) bool {
	_, ok := registry[uri]
	return ok
}

// PredicateTypes returns the URIs of every registered VSA adapter.
// Order is unspecified.
func PredicateTypes() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	return out
}

// FromParsed converts an already-parsed predicate payload into the
// normalized VSA shape, dispatching to the adapter registered for
// predicateType. Returns ErrNotVSA if no adapter handles
// predicateType.
func FromParsed(predicateType string, parsed any) (*VSA, error) {
	a, ok := registry[predicateType]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNotVSA, predicateType)
	}
	return a.Convert(parsed)
}

// FromStatement extracts a *VSA from an attestation.Statement. The
// statement's predicate must already be parsed (via the parsers
// registered in this package, which the envelope loader runs
// automatically). Returns ErrNotVSA if the statement's predicate
// type is not a registered VSA version.
func FromStatement(stmt attestation.Statement) (*VSA, error) {
	if stmt == nil {
		return nil, errors.New("nil statement")
	}
	pt := string(stmt.GetPredicateType())
	pred := stmt.GetPredicate()
	if pred == nil {
		return nil, errors.New("statement has no predicate")
	}
	return FromParsed(pt, pred.GetParsed())
}
