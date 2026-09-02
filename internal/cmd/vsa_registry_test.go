// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The VSA in testdata/source-note.jsonl was issued by
// https://github.com/slsa-framework/slsa-source-poc and signed by its
// compute_slsa_source.yml workflow at refs/heads/main. A registry
// binding the verifier lets --verifier name the id alone.
func TestVSAVerifierRegistry(t *testing.T) {
	t.Parallel()
	note := filepath.Join("testdata", "source-note.jsonl")
	const verifierID = "https://github.com/slsa-framework/slsa-source-poc"
	dir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
		return p
	}
	bound := write("bound.yaml", "verifiers:\n  - id: "+verifierID+"\n    issuer: https://token.actions.githubusercontent.com\n")
	released := write("released.yaml", "verifiers:\n  - id: "+verifierID+"\n    issuer: https://token.actions.githubusercontent.com\n    ref: semver-tag\n")
	other := write("other.yaml", "verifiers:\n  - id: "+verifierID+"\n    signer: sigstore::https://token.actions.githubusercontent.com::https://github.com/slsa-framework/slsa-source-poc/.github/workflows/release.yml@refs/heads/main\n")

	run := func(t *testing.T, registry string) (string, error) {
		t.Helper()
		opts := &vsaOptions{shared: &sharedOptions{}, AttestationPath: note, VerifierSpecs: []string{verifierID}, RegistryPath: registry}
		if err := opts.Validate(); err != nil {
			return "", err
		}
		var out bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetOut(&out)
		return out.String() + "", runVSA(cmd, opts)
	}

	t.Run("a verifier the embedded registry does not know is unbound", func(t *testing.T) {
		t.Parallel()
		opts := &vsaOptions{shared: &sharedOptions{}, AttestationPath: note, VerifierSpecs: []string{"https://verify.example.com"}}
		err := opts.Validate()
		require.ErrorContains(t, err, "has no authorized signer")
		assert.Contains(t, err.Error(), "--verifiers")
	})
	t.Run("the embedded registry binds the official SLSA source verifier", func(t *testing.T) {
		t.Parallel()
		opts := &vsaOptions{shared: &sharedOptions{}, AttestationPath: note, VerifierSpecs: []string{verifierID}}
		require.NoError(t, opts.Validate())
		assert.True(t, opts.shared.RequireSignatures, "a bound verifier requires signatures")
		var out bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetOut(&out)
		require.NoError(t, runVSA(cmd, opts))
		assert.Contains(t, out.String(), "PASS")
		assert.Contains(t, out.String(), "Signer is authorized")
	})
	t.Run("the registry binds the verifier", func(t *testing.T) {
		t.Parallel()
		opts := &vsaOptions{shared: &sharedOptions{}, AttestationPath: note, VerifierSpecs: []string{verifierID}, RegistryPath: bound}
		require.NoError(t, opts.Validate())
		assert.True(t, opts.shared.RequireSignatures, "a bound verifier requires signatures")
		var out bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetOut(&out)
		require.NoError(t, runVSA(cmd, opts))
		assert.Contains(t, out.String(), "PASS")
		assert.Contains(t, out.String(), "Signer is authorized")
	})
	t.Run("the registry's ref policy applies", func(t *testing.T) {
		t.Parallel()
		opts := &vsaOptions{shared: &sharedOptions{}, AttestationPath: note, VerifierSpecs: []string{verifierID}, RegistryPath: released}
		require.NoError(t, opts.Validate())
		var out bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetOut(&out)
		require.ErrorIs(t, runVSA(cmd, opts), ErrVerifyFailed)
		assert.Contains(t, out.String(), "a ref the registry does not allow")
	})
	t.Run("another workflow of the repository is not the signer", func(t *testing.T) {
		t.Parallel()
		opts := &vsaOptions{shared: &sharedOptions{}, AttestationPath: note, VerifierSpecs: []string{verifierID}, RegistryPath: other}
		require.NoError(t, opts.Validate())
		var out bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetOut(&out)
		require.ErrorIs(t, runVSA(cmd, opts), ErrVerifyFailed)
		assert.Contains(t, out.String(), "not authorized for this verifier")
	})
	t.Run("an explicit binding overrides the registry", func(t *testing.T) {
		t.Parallel()
		opts := &vsaOptions{shared: &sharedOptions{}, AttestationPath: note, VerifierSpecs: []string{verifierID + "=spiffe://example.com/other"}, RegistryPath: bound}
		require.NoError(t, opts.Validate())
		var out bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetOut(&out)
		require.ErrorIs(t, runVSA(cmd, opts), ErrVerifyFailed)
	})
	t.Run("a bad registry file is reported", func(t *testing.T) {
		t.Parallel()
		_, err := run(t, filepath.Join(dir, "missing.yaml"))
		require.ErrorContains(t, err, "--verifiers")
	})
}
