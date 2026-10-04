// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildFixtureFor writes a copy of the v1 build fixture whose subject is
// the given artifact file (by sha256), and returns both paths.
func buildFixtureFor(t *testing.T, dir string, content []byte) (attestationPath, artifactPath string) {
	t.Helper()
	artifactPath = filepath.Join(dir, "app.tgz")
	require.NoError(t, os.WriteFile(artifactPath, content, 0o600))
	sum := sha256.Sum256(content)

	raw, err := os.ReadFile(filepath.Join("..", "..", "pkg", "slsa", "testdata", "plain", "v1-build.intoto.json"))
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	doc["subject"] = []any{map[string]any{"name": "out/app.tgz", "digest": map[string]any{"sha256": hex.EncodeToString(sum[:])}}}
	data, err := json.Marshal(doc)
	require.NoError(t, err)
	attestationPath = filepath.Join(dir, "provenance.intoto.json")
	require.NoError(t, os.WriteFile(attestationPath, data, 0o600))
	return attestationPath, artifactPath
}

func TestRunBuildSubjects(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	attestationPath, artifactPath := buildFixtureFor(t, dir, []byte("release build"))
	otherPath := filepath.Join(dir, "other.tgz")
	require.NoError(t, os.WriteFile(otherPath, []byte("something else"), 0o600))
	wrongDigest := "sha256:" + strings.Repeat("ff", 32)

	for _, tc := range []struct {
		name       string
		artifacts  []string
		subjects   []string
		wantPass   bool
		wantOutput []string
	}{
		{
			name:     "no subjects: content-only verification, as before",
			wantPass: true,
		},
		{
			name: "the held artifact is the subject", artifacts: []string{artifactPath},
			wantPass: true, wantOutput: []string{"Subjects:", "[PASS]", "app.tgz", "matches out/app.tgz"},
		},
		{
			name: "a stated digest is the subject", subjects: []string{"sha256:" + fileSHA256(t, artifactPath)},
			wantPass: true, wantOutput: []string{"[PASS]"},
		},
		{
			name: "an artifact the attestation is not about fails", artifacts: []string{artifactPath, otherPath},
			wantPass: false, wantOutput: []string{"[PASS]", "[FAIL]", "other.tgz", "does not match", "1 of 2 expected subjects not found"},
		},
		{
			name: "a wrong digest fails", subjects: []string{wrongDigest},
			wantPass: false, wantOutput: []string{"[FAIL]", "does not match"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			shared := &sharedOptions{}
			shared.Raw = []string{"expected_source:git+https://example.com/repo", "trusted_builders:[https://example.com/builder]"}
			opts := &buildOptions{shared: shared, AttestationPath: attestationPath}
			opts.ArtifactPaths = tc.artifacts
			opts.SubjectSpecs = tc.subjects
			require.NoError(t, opts.Validate())

			var out bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetOut(&out)
			err := runBuild(cmd, opts)
			for _, want := range tc.wantOutput {
				assert.Contains(t, out.String(), want)
			}
			if tc.wantPass {
				require.NoError(t, err)
				assert.True(t, strings.HasPrefix(out.String(), "PASS"))
				return
			}
			require.ErrorIs(t, err, ErrVerifyFailed)
			assert.True(t, strings.HasPrefix(out.String(), "FAIL"))
		})
	}
}

// With --vsa, a run bound to artifacts summarizes the matched subjects.
func TestRunBuildSubjectsEmittedVSA(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	attestationPath, artifactPath := buildFixtureFor(t, dir, []byte("release build"))

	shared := &sharedOptions{}
	shared.Raw = []string{"expected_source:git+https://example.com/repo", "trusted_builders:[https://example.com/builder]"}
	opts := &buildOptions{shared: shared, AttestationPath: attestationPath}
	opts.ArtifactPaths = []string{artifactPath}
	opts.EmitVSA = true
	require.NoError(t, opts.Validate())

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	require.NoError(t, runBuild(cmd, opts))

	var stmt struct {
		Subject []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	require.NoError(t, json.Unmarshal(out.Bytes(), &stmt))
	require.Len(t, stmt.Subject, 1)
	assert.Equal(t, "out/app.tgz", stmt.Subject[0].Name)
	assert.Equal(t, fileSHA256(t, artifactPath), stmt.Subject[0].Digest["sha256"])
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// A buildType the catalog knows, with no expectation stated for it, is
// an execution error pointing at the flag; the flag skips the checks.
func TestRunBuildSkipBuildTypeChecks(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	raw, err := os.ReadFile(filepath.Join("..", "..", "pkg", "slsa", "testdata", "plain", "v1-build.intoto.json"))
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	bd, ok := doc["predicate"].(map[string]any)["buildDefinition"].(map[string]any)
	require.True(t, ok)
	bd["buildType"] = "https://example.com/test/buildType@v1"
	data, err := json.Marshal(doc)
	require.NoError(t, err)
	attestationPath := filepath.Join(dir, "provenance.intoto.json")
	require.NoError(t, os.WriteFile(attestationPath, data, 0o600))

	newOpts := func(skip bool) *buildOptions {
		shared := &sharedOptions{}
		shared.Raw = []string{"expected_source:git+https://example.com/repo", "trusted_builders:[https://example.com/builder]"}
		return &buildOptions{shared: shared, AttestationPath: attestationPath, SkipBuildTypeChecks: skip}
	}

	opts := newOpts(false)
	require.NoError(t, opts.Validate())
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	err = runBuild(cmd, opts)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrVerifyFailed, "an incomplete invocation is not a verification failure")
	assert.Contains(t, err.Error(), "expected_builder")
	assert.Contains(t, err.Error(), "--skip-buildtype-checks")

	opts = newOpts(true)
	require.NoError(t, opts.Validate())
	out.Reset()
	require.NoError(t, runBuild(cmd, opts))
	assert.True(t, strings.HasPrefix(out.String(), "PASS"))
}
