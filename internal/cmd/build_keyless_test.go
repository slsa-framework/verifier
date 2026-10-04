// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runKeylessBuild runs the build command over the keyless generator
// fixture with the given Rekor URL and returns the roster output.
func runKeylessBuild(t *testing.T, rekorURL string, require_ bool) (string, error) {
	t.Helper()
	shared := &sharedOptions{}
	shared.Raw = []string{
		"expected_source:github.com/slsa-framework/example-package",
		"trusted_builders:[https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml]",
	}
	shared.RekorURL = rekorURL
	shared.RequireSignatures = require_
	opts := &buildOptions{
		shared:              shared,
		AttestationPath:     filepath.Join("testdata", "keyless", "generator.intoto.jsonl"),
		SkipBuildTypeChecks: true,
		Verbose:             true,
	}
	require.NoError(t, opts.Validate())
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	err := runBuild(cmd, opts)
	return out.String(), err
}

// With the transparency log reachable, a legacy keyless envelope
// verifies end to end: the log entry vouches for the signature and the
// Fulcio identity flows into the builder binding — which refuses this
// builder for running from a branch instead of a release tag.
func TestRunBuildKeylessVerifies(t *testing.T) {
	t.Parallel()
	frozen, err := os.ReadFile(filepath.Join("testdata", "keyless", "rekor-response.json"))
	require.NoError(t, err)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body) //nolint:errcheck // best-effort drain
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write(frozen)
		assert.NoError(t, err)
	}))
	t.Cleanup(ts.Close)

	out, err := runKeylessBuild(t, ts.URL, false)
	require.ErrorIs(t, err, ErrVerifyFailed)
	assert.Contains(t, out, "[FAIL]  L2  builder-identity-bound")
	assert.Contains(t, out, "not a release tag", "the verified identity reached the binding")
	assert.Contains(t, out, "[PASS]  L1  source-repo-match")
}

// With the log unreachable the envelope stays unverifiable and the run
// degrades to content-only verification, builder.id an unproven claim.
func TestRunBuildKeylessOffline(t *testing.T) {
	t.Parallel()
	out, err := runKeylessBuild(t, "http://127.0.0.1:1", false)
	require.NoError(t, err)
	assert.Contains(t, out, "PASS")
	assert.Contains(t, out, "[SKIP]  L2  builder-identity-bound")
}

// Requiring signatures with the log unreachable fails the run, and the
// output says why: the log could not be queried, not that the
// signature was refuted.
func TestRunBuildKeylessOfflineRequired(t *testing.T) {
	t.Parallel()
	out, err := runKeylessBuild(t, "http://127.0.0.1:1", true)
	require.ErrorIs(t, err, ErrVerifyFailed)
	assert.Contains(t, out, "transparency log")
}
