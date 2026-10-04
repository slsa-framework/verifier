// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package eval_test

import (
	"testing"

	provenancev01 "github.com/in-toto/attestation/go/predicates/provenance/v01"
	provenancev02 "github.com/in-toto/attestation/go/predicates/provenance/v02"
	provenancev1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	sourceprovenance "github.com/slsa-framework/source-tool/pkg/provenance"
	"github.com/stretchr/testify/assert"

	"github.com/slsa-framework/verifier/pkg/slsa/eval"
)

func TestBuildTypeOfV1(t *testing.T) {
	t.Parallel()

	pred := &provenancev1.Provenance{
		BuildDefinition: &provenancev1.BuildDefinition{
			BuildType: "https://example.com/buildType@v1",
		},
	}
	assert.Equal(t, "https://example.com/buildType@v1", eval.BuildTypeOf(pred))
}

func TestBuildTypeOfV02(t *testing.T) {
	t.Parallel()

	pred := &provenancev02.Provenance{BuildType: "https://example.com/v02"}
	assert.Equal(t, "https://example.com/v02", eval.BuildTypeOf(pred))
}

func TestBuildTypeOfV01(t *testing.T) {
	t.Parallel()

	pred := &provenancev01.Provenance{
		Recipe: &provenancev01.Recipe{Type: "https://example.com/recipe@v0.1"},
	}
	assert.Equal(t, "https://example.com/recipe@v0.1", eval.BuildTypeOf(pred))
}

func TestBuildTypeOfSourceReturnsEmpty(t *testing.T) {
	t.Parallel()

	pred := &sourceprovenance.SourceProvenancePred{RepoUri: "https://github.com/x/y"}
	assert.Empty(t, eval.BuildTypeOf(pred))
}

func TestBuildTypeOfNilProvenance(t *testing.T) {
	t.Parallel()

	// Nil pointer with the right type — accessor chain should not panic.
	var p *provenancev1.Provenance
	assert.Empty(t, eval.BuildTypeOf(p))
}
