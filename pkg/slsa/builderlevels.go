// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
	"fmt"
	"strings"

	"github.com/carabiner-dev/attestation"

	"github.com/slsa-framework/verifier/pkg/slsa/eval"
)

// capBuilderLevel caps the computed level of a result at the level the
// caller trusts the builder of the provenance to reach, see
// WithBuilderLevels.
func capBuilderLevel(opts *VerificationOptions, statement attestation.Statement, r *Result) {
	if len(opts.BuilderLevels) == 0 {
		return
	}
	predicate, err := extractPredicate(statement)
	if err != nil {
		return
	}
	builderID := eval.BuilderIDOf(predicate)
	level, ok := builderLevel(opts.BuilderLevels, builderID)
	if !ok || r.SLSALevel <= level {
		return
	}
	r.SLSALevel = level
	r.Message = joinMessages(r.Message, fmt.Sprintf("SLSA level capped at %d, the level of builder %s", level, builderID))
}

// builderLevel returns the level of the builder with the id, the highest
// if several entries match it. An entry without an @ also matches the
// builder at any ref, as in the trusted_builders parameter.
func builderLevel(levels map[string]int, builderID string) (int, bool) {
	level, found := 0, false
	for id, l := range levels {
		if builderID != id && (strings.Contains(id, "@") || !strings.HasPrefix(builderID, id+"@")) {
			continue
		}
		if !found || l > level {
			level = l
		}
		found = true
	}
	return level, found
}
