// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package eval

import (
	provenancev01 "github.com/in-toto/attestation/go/predicates/provenance/v01"
	provenancev02 "github.com/in-toto/attestation/go/predicates/provenance/v02"
	provenancev1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	sourcetoolv1 "github.com/slsa-framework/protos/sourcetool/v1"
	sourceprovenance "github.com/slsa-framework/source-tool/pkg/provenance"
	"google.golang.org/protobuf/proto"
)

// SLSA predicate type URIs supported by the verifier. VSA predicate
// types live in pkg/slsa/vsa; they're parsed by adapters there rather
// than via the protojson path used here, so they're not registered
// in this map.
const (
	PredicateProvenanceV01 = "https://slsa.dev/provenance/v0.1"
	PredicateProvenanceV02 = "https://slsa.dev/provenance/v0.2"
	PredicateProvenanceV1  = "https://slsa.dev/provenance/v1"
	// The source track predicate types come from the shared protos module,
	// which defines both the final v1 types, published under the project.s
	// new name (source-tool, formerly slsa-source-poc), and the draft types
	// source-tool issued before the promotion. Both carry the same payload
	// and parse into the same protos.
	PredicateSourceProvenance   = sourcetoolv1.PredicateTypeSourceProvenanceDraft
	PredicateTagProvenance      = sourcetoolv1.PredicateTypeTagProvenanceDraft
	PredicateSourceProvenanceV1 = sourcetoolv1.PredicateTypeSourceProvenance
	PredicateTagProvenanceV1    = sourcetoolv1.PredicateTypeTagProvenance
)

// PredicateFactory returns an empty proto.Message of the matching predicate type.
type PredicateFactory func() proto.Message

// registeredPredicates maps predicate-type URIs to their proto factory.
// The factories are used to register descriptors with cel.Env and to
// parse predicate payloads. Track classification is intentionally not
// here: the controls package derives predicate tracks from the loaded
// YAML catalog (every control declares its track, every check names a
// predicate type) so adding new tracks to a predicate type is a YAML
// edit, not a Go edit.
var registeredPredicates = map[string]PredicateFactory{
	PredicateProvenanceV01:      func() proto.Message { return &provenancev01.Provenance{} },
	PredicateProvenanceV02:      func() proto.Message { return &provenancev02.Provenance{} },
	PredicateProvenanceV1:       func() proto.Message { return &provenancev1.Provenance{} },
	PredicateSourceProvenance:   func() proto.Message { return &sourceprovenance.SourceProvenancePred{} },
	PredicateTagProvenance:      func() proto.Message { return &sourceprovenance.TagProvenancePred{} },
	PredicateSourceProvenanceV1: func() proto.Message { return &sourceprovenance.SourceProvenancePred{} },
	PredicateTagProvenanceV1:    func() proto.Message { return &sourceprovenance.TagProvenancePred{} },
}

// IsKnownPredicateType reports whether the given URI matches a SLSA
// predicate type the verifier supports.
func IsKnownPredicateType(uri string) bool {
	_, ok := registeredPredicates[uri]
	return ok
}

// KnownPredicateTypes returns the list of supported predicate-type URIs.
func KnownPredicateTypes() []string {
	out := make([]string, 0, len(registeredPredicates))
	for k := range registeredPredicates {
		out = append(out, k)
	}
	return out
}

// NewPredicate returns an empty proto.Message for the given predicate type
// or false if the type is unknown.
func NewPredicate(predicateType string) (proto.Message, bool) {
	f, ok := registeredPredicates[predicateType]
	if !ok {
		return nil, false
	}
	return f(), true
}
