// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package vsa

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/carabiner-dev/attestation"
	collectorpred "github.com/carabiner-dev/collector/predicate"
	"github.com/carabiner-dev/collector/predicate/generic"
	vsav1 "github.com/in-toto/attestation/go/predicates/vsa/v1"
	"google.golang.org/protobuf/encoding/protojson"

	// Force pkg/slsa/predicate's init() to run before ours so it
	// finishes replacing collectorpred.Parsers with the SLSA-only
	// registry, and our additions below survive.
	_ "github.com/slsa-framework/verifier/pkg/slsa/predicate"
)

// v02Parser parses VSA v0.2 payloads through encoding/json into a
// v02Payload. The upstream proto definition uses json_name overrides
// that force snake_case in protojson, which doesn't match the
// camelCase format VSA v0.2 producers actually emit per the SLSA
// spec, so we bypass protojson for this version.
type v02Parser struct{}

// Parse implements attestation.PredicateParser.
func (v02Parser) Parse(data []byte) (attestation.Predicate, error) {
	p := &v02Payload{}
	if err := json.Unmarshal(data, p); err != nil {
		return nil, fmt.Errorf("parsing VSA v0.2 JSON: %w", err)
	}
	return &generic.Predicate{
		Type:   PredicateTypeV02,
		Parsed: p,
		Data:   data,
	}, nil
}

// SupportsType implements attestation.PredicateParser.
func (v02Parser) SupportsType(types ...attestation.PredicateType) bool {
	for _, t := range types {
		if string(t) == PredicateTypeV02 {
			return true
		}
	}
	return false
}

// v1Parser parses VSA v1 payloads through protojson into the upstream
// proto type. v1 omits the v0.2 json_name overrides, so its proto
// round-trips correctly through protojson.
type v1Parser struct{}

// Parse implements attestation.PredicateParser.
func (v1Parser) Parse(data []byte) (attestation.Predicate, error) {
	msg := &vsav1.VerificationSummary{}
	// Discard unknown producer extension fields rather than rejecting the VSA.
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(data, msg); err != nil {
		if isWrongFormat(err) {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, fmt.Errorf("parsing VSA v1 JSON: %w", err)
	}
	return &generic.Predicate{
		Type:   PredicateTypeV1,
		Parsed: msg,
		Data:   data,
	}, nil
}

// SupportsType implements attestation.PredicateParser.
func (v1Parser) SupportsType(types ...attestation.PredicateType) bool {
	for _, t := range types {
		if string(t) == PredicateTypeV1 {
			return true
		}
	}
	return false
}

// isWrongFormat mirrors the helper in pkg/slsa/predicate — translates
// protojson "doesn't match this proto" errors into the collector's
// ErrNotCorrectFormat sentinel so parser dispatch keeps trying other
// candidates instead of bubbling up.
func isWrongFormat(err error) bool {
	s := err.Error()
	return strings.Contains(s, "syntax error") ||
		strings.Contains(s, "unknown field") ||
		strings.Contains(s, "invalid value")
}

// init adds the VSA parsers to the collector's predicate-parser
// registry. The blank import above ensures pkg/slsa/predicate has
// already replaced collectorpred.Parsers with the SLSA-only set by
// the time this runs, so we're adding to a known-good map.
func init() {
	collectorpred.Parsers[PredicateTypeV02] = v02Parser{}
	collectorpred.Parsers[PredicateTypeV1] = v1Parser{}
}
