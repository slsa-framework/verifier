// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package eval

import (
	provenancev01 "github.com/in-toto/attestation/go/predicates/provenance/v01"
	provenancev02 "github.com/in-toto/attestation/go/predicates/provenance/v02"
	provenancev1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	"google.golang.org/protobuf/proto"
)

// BuildTypeOf extracts the build provenance buildType URI from a parsed
// SLSA build predicate, normalising across versions:
//
//   - v0.1 → Provenance.Recipe.Type
//   - v0.2 → Provenance.BuildType
//   - v1.0 → Provenance.BuildDefinition.BuildType
//
// Returns "" for the SLSA source predicate or any non-build predicate
// (which carry no buildType concept).
func BuildTypeOf(predicate proto.Message) string {
	switch p := predicate.(type) {
	case *provenancev1.Provenance:
		return p.GetBuildDefinition().GetBuildType()
	case *provenancev02.Provenance:
		return p.GetBuildType()
	case *provenancev01.Provenance:
		return p.GetRecipe().GetType()
	}
	return ""
}
