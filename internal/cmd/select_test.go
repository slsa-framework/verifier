// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/verifier/pkg/attestation"
)

// testdata/source-note.jsonl is a commit's git note as sourcetool
// stores it: the source provenance for the commit followed by the VSA
// sourcetool issued for it, both Sigstore bundles. Each subcommand
// picks the attestation it verifies out of it.
const noteCommit = "1824b8fb8980a7fae36eb325408d35c344c04fd9"

func TestCommandsSelectFromANote(t *testing.T) {
	t.Parallel()
	note := filepath.Join("testdata", "source-note.jsonl")

	t.Run("source picks the source provenance", func(t *testing.T) {
		t.Parallel()
		opts := &sourceOptions{shared: &sharedOptions{}, Level: "1", AttestationPath: note, SubjectArg: noteCommit, ExpectedRepo: "https://github.com/puerco/lab", ExpectedBranch: "refs/heads/master"}
		require.NoError(t, opts.Validate())
		var out bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetOut(&out)
		err := runSource(cmd, opts)
		if err != nil {
			require.ErrorIs(t, err, ErrVerifyFailed, "selection must not be an execution error")
		}
		assert.Contains(t, out.String(), "Core controls:")
		assert.Contains(t, out.String(), "source-repo-match")
	})

	t.Run("vsa picks the VSA", func(t *testing.T) {
		t.Parallel()
		opts := &vsaOptions{shared: &sharedOptions{}, AttestationPath: note, VerifierSpecs: []string{"https://github.com/slsa-framework/slsa-source-poc"}, AllowUnbound: true}
		require.NoError(t, opts.Validate())
		var out bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetOut(&out)
		err := runVSA(cmd, opts)
		if err != nil {
			require.ErrorIs(t, err, ErrVerifyFailed, "selection must not be an execution error")
		}
		assert.Contains(t, out.String(), "Verifier")
	})

	t.Run("build finds no provenance", func(t *testing.T) {
		t.Parallel()
		shared := &sharedOptions{}
		shared.Raw = []string{"expected_source:x", "trusted_builders:[x]"}
		opts := &buildOptions{shared: shared, AttestationPath: note}
		require.NoError(t, opts.Validate())
		err := runBuild(&cobra.Command{}, opts)
		require.ErrorIs(t, err, attestation.ErrNoApplicableAttestation)
		assert.Contains(t, err.Error(), "build provenance")
	})

	t.Run("source about another commit finds nothing", func(t *testing.T) {
		t.Parallel()
		opts := &sourceOptions{shared: &sharedOptions{}, Level: "1", AttestationPath: note, SubjectArg: "b797d53cd7fe550be0dcddb05594343dce3e4cc5", ExpectedRepo: "https://github.com/puerco/lab"}
		require.NoError(t, opts.Validate())
		err := runSource(&cobra.Command{}, opts)
		require.ErrorIs(t, err, attestation.ErrNoApplicableAttestation)
	})
}
