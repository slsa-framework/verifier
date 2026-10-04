// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/policylabs/collector/envelope"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/verifier/pkg/slsa"
	"github.com/slsa-framework/verifier/pkg/slsa/controls"
)

// emittedVSA runs emitVSA over the source fixture with the given result
// and decodes the predicate of the emitted statement.
func emittedVSA(t *testing.T, result *slsa.Result, track controls.Track) map[string]any {
	t.Helper()
	envs, err := envelope.Parsers.ParseFiles([]string{
		filepath.Join("..", "..", "pkg", "slsa", "testdata", "plain", "source.intoto.json"),
	})
	require.NoError(t, err)
	require.Len(t, envs, 1)

	var out bytes.Buffer
	require.NoError(t, emitVSA(&out, envs[0].GetStatement(), result, track))

	var stmt struct {
		Predicate map[string]any `json:"predicate"`
	}
	require.NoError(t, json.Unmarshal(out.Bytes(), &stmt))
	return stmt.Predicate
}

// A FAILED summary must not carry verifiedLevels: consumers read that
// field on its own, and a level the run did not vouch for would let a
// policy accept a failed verification.
func TestEmitVSAVerifiedLevelsFollowTheVerdict(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		result     *slsa.Result
		track      controls.Track
		wantResult string
		wantLevels []any // nil: the field must be absent or empty
	}{
		{
			name:       "passed at level 3",
			result:     &slsa.Result{Status: slsa.StatusPass, SLSALevel: 3},
			track:      controls.TrackSource,
			wantResult: "PASSED", wantLevels: []any{"SLSA_SOURCE_LEVEL_3"},
		},
		{
			name:       "passed at level 2 on the build track",
			result:     &slsa.Result{Status: slsa.StatusPass, SLSALevel: 2},
			track:      controls.TrackBuild,
			wantResult: "PASSED", wantLevels: []any{"SLSA_BUILD_LEVEL_2"},
		},
		{
			// Core controls clean at L4, but a user control (or MinLevel,
			// or the signature gate) failed the run.
			name:       "failed with a computed level",
			result:     &slsa.Result{Status: slsa.StatusFail, SLSALevel: 4},
			track:      controls.TrackSource,
			wantResult: "FAILED", wantLevels: nil,
		},
		{
			name:       "passed with nothing established",
			result:     &slsa.Result{Status: slsa.StatusPass, SLSALevel: 0},
			track:      controls.TrackSource,
			wantResult: "PASSED", wantLevels: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pred := emittedVSA(t, tc.result, tc.track)
			assert.Equal(t, tc.wantResult, pred["verificationResult"])
			if tc.wantLevels == nil {
				assert.Empty(t, pred["verifiedLevels"])
				return
			}
			levels, ok := pred["verifiedLevels"].([]any)
			require.True(t, ok, "verifiedLevels must be a list, got %T", pred["verifiedLevels"])
			assert.Equal(t, tc.wantLevels, levels)
		})
	}
}

// The emitted verifier.id is the identity the run was configured with,
// falling back to the SLSA verifier project's URL.
func TestEmitVSAVerifierID(t *testing.T) {
	t.Parallel()

	pred := emittedVSA(t, &slsa.Result{Status: slsa.StatusPass, SLSALevel: 1, VerifierID: "https://verify.example.com"}, controls.TrackSource)
	verifier, ok := pred["verifier"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "https://verify.example.com", verifier["id"])

	pred = emittedVSA(t, &slsa.Result{Status: slsa.StatusPass, SLSALevel: 1}, controls.TrackSource)
	verifier, ok = pred["verifier"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "https://github.com/slsa-framework/verifier", verifier["id"])
}

func TestVSAOutputOptionsVerifierID(t *testing.T) {
	t.Parallel()

	// Bound to a command, the flag defaults to the SLSA verifier project URL.
	o := &vsaOutputOptions{}
	o.AddFlags(&cobra.Command{})
	assert.Equal(t, defaultVerifierID, o.VerifierID)
	require.NoError(t, o.Validate())

	o.VerifierID = "https://verify.example.com"
	require.NoError(t, o.Validate())

	// Options built without the flags get the default on Validate.
	o = &vsaOutputOptions{}
	require.NoError(t, o.Validate())
	assert.Equal(t, defaultVerifierID, o.VerifierID)
}
