// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/slsa-framework/verifier/pkg/attestation"
	"github.com/slsa-framework/verifier/pkg/slsa/eval"
	"github.com/slsa-framework/verifier/pkg/slsa/vsa"
)

// Predicate types each subcommand verifies, used to pick the right
// attestation out of a file holding several.
var (
	buildPredicateTypes = []string{
		eval.PredicateProvenanceV1, eval.PredicateProvenanceV02, eval.PredicateProvenanceV01,
	}
	sourceProvenanceTypes = []string{eval.PredicateSourceProvenanceV1, eval.PredicateSourceProvenance}
	tagProvenanceTypes    = []string{eval.PredicateTagProvenanceV1, eval.PredicateTagProvenance}
	vsaPredicateTypes     = []string{vsa.PredicateTypeV1, vsa.PredicateTypeV02}
)

// loadEnvelope fetches the attestations at path — a file or a
// directory — and picks the one the selection describes. A path with
// one attestation yields it as is.
func loadEnvelope(ctx context.Context, path string, sel *attestation.Selection) (attestation.Envelope, error) {
	envs, err := attestation.New().Fetch(ctx, path)
	if err != nil {
		return nil, err
	}
	return attestation.Select(envs, sel)
}

// checkAttestationPath validates the attestation argument: it must
// name an existing file or directory.
func checkAttestationPath(path string) error {
	if path == "" {
		return errors.New("attestation path is required")
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("attestation file: %w", err)
	}
	return nil
}
