// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package predicate registers SLSA-only attestation.PredicateParser
// implementations as the collector's global predicate parser registry.
//
// Importing this package replaces github.com/policylabs/collector's
// shipped predicate parser map (which covers SBOMs, VEX, OSV, …) with the
// SLSA build (v0.1, v0.2, v1.0) and SLSA source predicate types only,
// using the upstream proto definitions from
// github.com/in-toto/attestation/go/predicates/provenance and
// github.com/slsa-framework/source-tool/pkg/provenance.
package predicate

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/policylabs/attestation"
	collectorpred "github.com/policylabs/collector/predicate"
	"github.com/policylabs/collector/predicate/generic"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/slsa-framework/verifier/pkg/slsa/eval"
)

// Parser handles a single SLSA predicate type by unmarshalling JSON into
// the upstream proto message registered for that type in the eval package.
type Parser struct {
	predicateType attestation.PredicateType
}

// NewParser returns a Parser for the given SLSA predicate type. The type
// must be registered in the eval package; otherwise NewParser returns nil
// and false.
func NewParser(predicateType attestation.PredicateType) (*Parser, bool) {
	if !eval.IsKnownPredicateType(string(predicateType)) {
		return nil, false
	}
	return &Parser{predicateType: predicateType}, true
}

// Parse unmarshals data into the proto message backing this parser's
// predicate type and wraps it in a generic.Predicate so the collector
// can thread it through statements and envelopes. After unmarshalling,
// nil singular sub-messages are replaced with zero-valued instances so
// CEL expressions can chain through intermediate fields without
// erroring on missing payload data.
func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	msg, _ := eval.NewPredicate(string(p.predicateType))
	normalized, err := normalizeFieldNames(p.predicateType, data)
	if err != nil {
		return nil, fmt.Errorf("parsing %s predicate: %w", p.predicateType, err)
	}
	// Real-world provenance carries producer-specific fields the SLSA
	// protos do not define; they are not a reason to reject it.
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(normalized, msg); err != nil {
		if isWrongFormat(err) {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, fmt.Errorf("parsing %s predicate: %w", p.predicateType, err)
	}
	eval.FillNilMessages(msg)
	return &generic.Predicate{
		Type:   p.predicateType,
		Parsed: msg,
		Data:   data,
	}, nil
}

// fieldAliases maps, per predicate type, JSON field names producers use
// to the names the proto defines. The v0.2 provenance emitted by
// in-toto-golang and slsa-github-generator spells the invocation id
// buildInvocationID, which protojson would treat as an unknown field and
// drop, failing the invocation-id control for every real v0.2 build.
var fieldAliases = map[attestation.PredicateType]map[string]map[string]string{
	"https://slsa.dev/provenance/v0.2": {
		"metadata": {"buildInvocationID": "buildInvocationId"},
	},
}

// normalizeFieldNames rewrites aliased field names in data to the names
// the proto defines. Data without aliases is returned untouched.
func normalizeFieldNames(predicateType attestation.PredicateType, data []byte) ([]byte, error) {
	aliases, ok := fieldAliases[predicateType]
	if !ok {
		return data, nil
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return data, nil //nolint:nilerr // let protojson report the syntax error
	}
	changed := false
	for section, names := range aliases {
		raw, ok := doc[section]
		if !ok {
			continue
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			continue
		}
		for from, to := range names {
			v, ok := fields[from]
			if !ok {
				continue
			}
			if _, taken := fields[to]; !taken {
				fields[to] = v
			}
			delete(fields, from)
			changed = true
		}
		if changed {
			out, err := json.Marshal(fields)
			if err != nil {
				return nil, err
			}
			doc[section] = out
		}
	}
	if !changed {
		return data, nil
	}
	return json.Marshal(doc)
}

// SupportsType reports whether this parser handles any of types.
func (p *Parser) SupportsType(types ...attestation.PredicateType) bool {
	for _, t := range types {
		if t == p.predicateType {
			return true
		}
	}
	return false
}

// isWrongFormat translates protojson "doesn't match this proto" errors
// into the collector's ErrNotCorrectFormat sentinel so its parser dispatch
// keeps trying the remaining parsers instead of bubbling up.
func isWrongFormat(err error) bool {
	s := err.Error()
	return strings.Contains(s, "syntax error") ||
		strings.Contains(s, "unknown field") ||
		strings.Contains(s, "invalid value")
}

// Parsers is the SLSA-only predicate parser registry — one Parser per
// predicate type known to the eval package.
var Parsers = func() collectorpred.ParsersList {
	out := collectorpred.ParsersList{}
	for _, pt := range eval.KnownPredicateTypes() {
		p, _ := NewParser(attestation.PredicateType(pt))
		out[attestation.PredicateType(pt)] = p
	}
	return out
}()

// init replaces the collector's global predicate parser registry with the
// SLSA-only set above. After this package is imported (directly or
// transitively), envelope.Parsers and statement.Parsers parse predicates
// through this package only.
func init() {
	collectorpred.Parsers = Parsers
}
