// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package slsa_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/verifier/pkg/slsa"
)

// The fixture records every field the level 3 controls check, but its
// builder reaches only the level the caller trusts it with.
func TestVerifyBuilderLevels(t *testing.T) {
	t.Parallel()

	const builder = "https://example.com/builder/v0.2"

	for _, tc := range []struct {
		name     string
		levels   map[string]int
		minLevel int
		status   slsa.Status
		level    int
	}{
		{name: "not capped", level: 3, status: slsa.StatusPass},
		{name: "capped", levels: map[string]int{builder: 1}, level: 1, status: slsa.StatusPass},
		{name: "the minimum selects the controls", levels: map[string]int{builder: 1}, minLevel: 2, level: 1, status: slsa.StatusPass},
		{name: "a higher level does not raise", levels: map[string]int{builder: 3}, level: 3, status: slsa.StatusPass},
		{name: "other builders", levels: map[string]int{"https://example.com/other": 1}, level: 3, status: slsa.StatusPass},
		{name: "an entry without a ref", levels: map[string]int{"https://example.com/builder": 1}, level: 3, status: slsa.StatusPass},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			v, err := slsa.New()
			require.NoError(t, err)

			res, err := v.Verify(
				context.Background(),
				loadFixture(t, "v02-build.intoto.json"),
				slsa.WithParam("expected_source", "git+https://example.com/repo"),
				slsa.WithParam("trusted_builders", []string{builder}),
				slsa.WithMinLevel(tc.minLevel),
				slsa.WithBuilderLevels(tc.levels),
			)
			require.NoError(t, err)
			assert.Equal(t, tc.status, res.Status)
			assert.Equal(t, tc.level, res.SLSALevel)
		})
	}
}

func TestWithBuilderLevelsRejectsInvalidLevels(t *testing.T) {
	t.Parallel()

	for _, levels := range []map[string]int{{"": 2}, {"https://example.com/builder": 0}, {"https://example.com/builder": 5}} {
		opts := slsa.DefaultVerificationOptions()
		require.Error(t, slsa.WithBuilderLevels(levels)(&opts))
	}
}
