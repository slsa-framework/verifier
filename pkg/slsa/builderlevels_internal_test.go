// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuilderLevelMatchesRefs(t *testing.T) {
	t.Parallel()

	levels := map[string]int{
		"https://example.com/builder":              2,
		"https://example.com/release@refs/tags/v1": 3,
	}
	for _, tc := range []struct {
		builderID string
		level     int
		found     bool
	}{
		{builderID: "https://example.com/builder", level: 2, found: true},
		{builderID: "https://example.com/builder@refs/heads/main", level: 2, found: true},
		{builderID: "https://example.com/builder2"},
		{builderID: "https://example.com/release@refs/tags/v1", level: 3, found: true},
		{builderID: "https://example.com/release@refs/tags/v2"},
		{builderID: "https://example.com/release"},
	} {
		level, found := builderLevel(levels, tc.builderID)
		assert.Equal(t, tc.found, found, tc.builderID)
		assert.Equal(t, tc.level, level, tc.builderID)
	}
}
