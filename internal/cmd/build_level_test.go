// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseBuildLevel(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   string
		want int
		bad  bool
	}{
		{in: "0", want: 0},
		{in: "2", want: 2},
		{in: " 3 ", want: 3},
		{in: "SLSA_BUILD_LEVEL_1", want: 1},
		{in: "slsa_build_level_3", want: 3},
		{in: "4", bad: true},
		{in: "-1", bad: true},
		{in: "L2", bad: true},
		{in: "SLSA_SOURCE_LEVEL_2", bad: true},
		{in: "", want: 0},
	} {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got, err := parseBuildLevel(tc.in)
			if tc.bad {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// With --level, controls above the required level are informative:
// a failing L2 control caps the level instead of failing a run that
// only requires L1, and fails one that requires L2.
func TestRunBuildLevel(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	attestationPath, _ := buildFixtureFor(t, dir, []byte("release build"))

	run := func(t *testing.T, level string, trusted string) (string, error) {
		t.Helper()
		shared := &sharedOptions{}
		shared.Raw = []string{"expected_source:git+https://example.com/repo", "trusted_builders:[" + trusted + "]"}
		opts := &buildOptions{shared: shared, AttestationPath: attestationPath, Level: level}
		require.NoError(t, opts.Validate())
		var out bytes.Buffer
		cmd := &cobra.Command{}
		cmd.SetOut(&out)
		err := runBuild(cmd, opts)
		return out.String(), err
	}

	t.Run("default requires every control", func(t *testing.T) {
		t.Parallel()
		out, err := run(t, "0", "https://other.example.com/builder")
		require.ErrorIs(t, err, ErrVerifyFailed)
		assert.Contains(t, out, "FAIL")
		assert.Contains(t, out, "[FAIL]  L2  builder-id-trusted")
	})
	t.Run("level 1 makes the L2 failure informative", func(t *testing.T) {
		t.Parallel()
		out, err := run(t, "1", "https://other.example.com/builder")
		require.NoError(t, err)
		assert.Contains(t, out, "PASS\nSLSA Level: 1")
		assert.Contains(t, out, "[FAIL]  L2  builder-id-trusted")
	})
	t.Run("level 2 is not reached", func(t *testing.T) {
		t.Parallel()
		out, err := run(t, "SLSA_BUILD_LEVEL_2", "https://other.example.com/builder")
		require.ErrorIs(t, err, ErrVerifyFailed)
		assert.Contains(t, out, "SLSA level 1 is below the required level 2")
	})
	t.Run("level 3 reached", func(t *testing.T) {
		t.Parallel()
		out, err := run(t, "3", "https://example.com/builder")
		require.NoError(t, err)
		assert.Contains(t, out, "PASS\nSLSA Level: 3")
	})
	t.Run("bad level is rejected", func(t *testing.T) {
		t.Parallel()
		opts := &buildOptions{shared: &sharedOptions{}, AttestationPath: attestationPath, Level: "9"}
		require.ErrorContains(t, opts.Validate(), "invalid build level")
	})
}
