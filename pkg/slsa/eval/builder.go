// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package eval

import (
	provenancev01 "github.com/in-toto/attestation/go/predicates/provenance/v01"
	provenancev02 "github.com/in-toto/attestation/go/predicates/provenance/v02"
	provenancev1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	"google.golang.org/protobuf/proto"
)

// BuilderIDOf extracts the builder id from a parsed SLSA build
// predicate, normalising across versions:
//
//   - v0.1 → Provenance.Builder.Id
//   - v0.2 → Provenance.Builder.Id
//   - v1.0 → Provenance.RunDetails.Builder.Id
//
// Returns "" for predicates that carry no builder (the source track).
func BuilderIDOf(predicate proto.Message) string {
	switch p := predicate.(type) {
	case *provenancev1.Provenance:
		return p.GetRunDetails().GetBuilder().GetId()
	case *provenancev02.Provenance:
		return p.GetBuilder().GetId()
	case *provenancev01.Provenance:
		return p.GetBuilder().GetId()
	}
	return ""
}
