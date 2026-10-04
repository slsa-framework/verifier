// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package controls_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/verifier/pkg/slsa/controls"
)

const sampleControl = `id: my-check
title: Custom user check
track: build
checks:
  - predicateType: https://slsa.dev/provenance/v1
    expression: "true"
`

const sampleControlMultiDoc = `id: a
title: A
track: build
checks:
  - predicateType: https://slsa.dev/provenance/v1
    expression: "true"
---
id: b
title: B
track: build
checks:
  - predicateType: https://slsa.dev/provenance/v1
    expression: "false"
`

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func TestLoadSingleFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := writeFile(t, dir, "ctrl.yaml", sampleControl)

	got, err := controls.Load(path)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "my-check", got[0].ID)
}

func TestLoadMultiDocFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := writeFile(t, dir, "ctrl.yaml", sampleControlMultiDoc)

	got, err := controls.Load(path)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "a", got[0].ID)
	assert.Equal(t, "b", got[1].ID)
}

func TestLoadDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, dir, "one.yaml", sampleControl)
	// Subdirectory walked recursively.
	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(sub, 0o700))
	writeFile(t, sub, "two.yaml", sampleControlMultiDoc)
	// Non-YAML files are ignored.
	writeFile(t, dir, "README.md", "not yaml")

	got, err := controls.Load(dir)
	require.NoError(t, err)
	assert.Len(t, got, 3)
}

func TestLoadInvalidControlReturnsError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// Missing title — Validate fails.
	path := writeFile(t, dir, "bad.yaml", `id: x
track: build
checks:
  - predicateType: https://slsa.dev/provenance/v1
    expression: "true"
`)
	_, err := controls.Load(path)
	assert.Error(t, err)
}

func TestLoadMissingPath(t *testing.T) {
	t.Parallel()

	_, err := controls.Load(filepath.Join(t.TempDir(), "nope"))
	assert.Error(t, err)
}

func TestLoadEmptyDir(t *testing.T) {
	t.Parallel()

	got, err := controls.Load(t.TempDir())
	require.NoError(t, err)
	assert.Empty(t, got)
}
