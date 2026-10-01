// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuilderOptionsValidate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	registryPath := filepath.Join(dir, "builders.yaml")
	require.NoError(t, os.WriteFile(registryPath, []byte(
		"builders:\n  - id: https://ci.example.com/builder\n    signer: spiffe://example.com/ci/builder\n    title: from file\n"), 0o600))

	t.Run("nothing set uses the embedded registry", func(t *testing.T) {
		t.Parallel()
		opts := &builderOptions{}
		require.NoError(t, opts.Validate())
		assert.Nil(t, opts.Registry())
	})

	t.Run("bindings and a file extend the embedded registry", func(t *testing.T) {
		t.Parallel()
		opts := &builderOptions{
			RegistryPath: registryPath,
			BuilderSpecs: []string{
				"https://ci.example.com/other=https://issuer.example.com",
				"https://ci.example.com/builder=spiffe://example.com/ci/override",
			},
		}
		require.NoError(t, opts.Validate())
		reg := opts.Registry()
		require.NotNil(t, reg)
		assert.NotNil(t, reg.Lookup("https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml"), "embedded entries are kept")
		assert.Equal(t, "https://issuer.example.com", reg.Lookup("https://ci.example.com/other").Issuer)
		assert.Equal(t, "spiffe://example.com/ci/override", reg.Lookup("https://ci.example.com/builder").SignerSpec(), "--builder overrides --builders")
	})

	t.Run("every bad value is reported", func(t *testing.T) {
		t.Parallel()
		opts := &builderOptions{
			RegistryPath: filepath.Join(dir, "missing.yaml"),
			BuilderSpecs: []string{"no-equals", "https://ci.example.com/b@refs/tags/v1=https://issuer.example.com"},
		}
		err := opts.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--builders")
		assert.Contains(t, err.Error(), `"no-equals"`)
		assert.Contains(t, err.Error(), "must not carry a ref")
		assert.Nil(t, opts.Registry())
	})
}

func TestBuilderOptionsLevels(t *testing.T) {
	t.Parallel()

	opts := &builderOptions{LevelSpecs: []string{
		"https://ci.example.com/builder=1",
		"https://ci.example.com/build?config=x=SLSA_BUILD_LEVEL_2",
	}}
	require.NoError(t, opts.Validate())
	assert.Equal(t, map[string]int{
		"https://ci.example.com/builder":        1,
		"https://ci.example.com/build?config=x": 2,
	}, opts.Levels())
	assert.Nil(t, opts.Registry())

	for _, spec := range []string{"https://ci.example.com/builder", "=1", "https://ci.example.com/builder=0", "https://ci.example.com/builder=4"} {
		opts := &builderOptions{LevelSpecs: []string{spec}}
		require.Error(t, opts.Validate(), spec)
	}
}
