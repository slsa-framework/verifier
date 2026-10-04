// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testdataDir = "../../internal/cmd/testdata"

func TestFetch(t *testing.T) {
	t.Parallel()
	v := New()
	ctx := context.Background()

	t.Run("a JSON lines file yields every attestation", func(t *testing.T) {
		t.Parallel()
		envs, err := v.Fetch(ctx, testdataDir+"/source-note.jsonl")
		require.NoError(t, err)
		assert.Len(t, envs, 2)
	})
	t.Run("a directory yields the attestations of every file", func(t *testing.T) {
		t.Parallel()
		envs, err := v.Fetch(ctx, testdataDir)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(envs), 3, "the note's two plus the DSSE VSAs")
	})
	t.Run("a single-attestation file", func(t *testing.T) {
		t.Parallel()
		envs, err := v.Fetch(ctx, testdataDir+"/forged-vsa.dsse.json")
		require.NoError(t, err)
		assert.Len(t, envs, 1)
	})
	t.Run("a missing path", func(t *testing.T) {
		t.Parallel()
		_, err := v.Fetch(ctx, testdataDir+"/missing.json")
		require.Error(t, err)
	})
	t.Run("Load wants exactly one", func(t *testing.T) {
		t.Parallel()
		_, err := v.Load(testdataDir + "/source-note.jsonl")
		require.ErrorContains(t, err, "expected one attestation, got 2")
		env, err := v.Load(testdataDir + "/forged-vsa.dsse.json")
		require.NoError(t, err)
		assert.NotNil(t, env)
	})
}
