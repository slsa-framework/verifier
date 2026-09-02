// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sapi "github.com/carabiner-dev/signer/api/v1"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSourceLevel(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		value   string
		want    int
		wantErr bool
	}{
		{"0", 0, true}, // no SLSA source level 0; would map to the strictest mode
		{"1", 1, false},
		{"4", 4, false},
		{"SLSA_SOURCE_LEVEL_3", 3, false},
		{"slsa_source_level_2", 2, false},
		{" 2 ", 2, false},
		{"5", 0, true},
		{"-1", 0, true},
		{"", 0, true},
		{"SLSA_BUILD_LEVEL_3", 0, true},
		{"three", 0, true},
	} {
		got, err := parseSourceLevel(tc.value)
		if tc.wantErr {
			require.Error(t, err, "value %q", tc.value)
			continue
		}
		require.NoError(t, err, "value %q", tc.value)
		assert.Equal(t, tc.want, got, "value %q", tc.value)
	}
}

func TestSourceOptionsOfficialAddsIdentities(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "att.json")
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0o600))

	opts := &sourceOptions{
		shared:          &sharedOptions{},
		AttestationPath: path,
		Level:           "1",
		Official:        true,
	}
	require.NoError(t, opts.Validate())
	assert.Len(t, opts.Signers, 3, "official flag should add the current and both legacy identities")
	assert.True(t, opts.shared.RequireSignatures, "official implies --require-signatures")
	assert.Equal(t, 1, opts.MinLevel)

	// The current workflow is accepted at any ref, the legacy ones only from main
	matches := func(subject string) bool {
		signer := &sapi.Identity{Sigstore: &sapi.IdentitySigstore{Issuer: officialSourceIssuer, Identity: subject}}
		for _, id := range opts.Signers {
			if (&sapi.SignatureVerification{Identities: []*sapi.Identity{signer}}).MatchesIdentity(id) {
				return true
			}
		}
		return false
	}
	const currentWorkflow = "https://github.com/slsa-framework/actions/.github/workflows/compute_slsa_source.yml"
	assert.True(t, matches(currentWorkflow+"@dea965cdca5e0cb422bf7b2653c9d15f678ad01c"))
	assert.True(t, matches(currentWorkflow+"@refs/tags/v0.1.0"))
	assert.True(t, matches("https://github.com/slsa-framework/source-actions/.github/workflows/compute_slsa_source.yml@refs/heads/main"))
	assert.True(t, matches("https://github.com/slsa-framework/slsa-source-poc/.github/workflows/compute_slsa_source.yml@refs/heads/main"))
	assert.False(t, matches("https://github.com/slsa-framework/source-actions/.github/workflows/compute_slsa_source.yml@refs/tags/v0.1.0"))
	assert.False(t, matches("https://github.com/slsa-framework/actions-fork/.github/workflows/compute_slsa_source.yml@refs/heads/main"))
	assert.False(t, matches("https://github.com/slsa-framework/actions/.github/workflows/release.yaml@refs/heads/main"))
}

func TestParseSinceDate(t *testing.T) {
	t.Parallel()

	got, err := parseSinceDate("2025-08-01T10:30:00Z")
	require.NoError(t, err)
	assert.Equal(t, "2025-08-01T10:30:00Z", got)

	got, err = parseSinceDate("2025-08-01")
	require.NoError(t, err)
	assert.Equal(t, "2025-08-01T00:00:00Z", got)

	_, err = parseSinceDate("August 1st")
	require.Error(t, err)
	_, err = parseSinceDate("2025-13-45")
	assert.Error(t, err)
}

func TestSourceOptionsExpectationFlagsFeedParams(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "att.json")
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0o600))

	opts := &sourceOptions{
		shared:          &sharedOptions{},
		AttestationPath: path,
		Level:           "1",
		ExpectedRepo:    "https://github.com/example/repo",
		ExpectedBranch:  "refs/heads/main",
		Since:           "2025-01-01",
	}
	require.NoError(t, opts.Validate())
	assert.Equal(t, "https://github.com/example/repo", opts.shared.Params["expected_source_repo"])
	assert.Equal(t, "refs/heads/main", opts.shared.Params["expected_branch"])
	assert.Equal(t, "2025-01-01T00:00:00Z", opts.shared.Params["enforced_since"])

	// The dedicated flags win over equivalent --param entries.
	opts.shared.Raw = []string{"expected_branch:refs/heads/other"}
	require.NoError(t, opts.Validate())
	assert.Equal(t, "refs/heads/main", opts.shared.Params["expected_branch"])

	// A malformed --since is a validation error.
	opts.Since = "not a date"
	assert.Error(t, opts.Validate())
}

func TestSourceOptionsValidateLevel(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "att.json")
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0o600))

	opts := &sourceOptions{
		shared:          &sharedOptions{},
		AttestationPath: path,
		Level:           "SLSA_SOURCE_LEVEL_4",
	}
	require.NoError(t, opts.Validate())
	assert.Equal(t, 4, opts.MinLevel)
	assert.Empty(t, opts.Signers)
	assert.False(t, opts.shared.RequireSignatures)

	opts = &sourceOptions{
		shared:          &sharedOptions{},
		AttestationPath: path,
		Level:           "9",
	}
	assert.Error(t, opts.Validate())
}

// A malformed --param must be reported, not turn into a nil-map panic
// when the expectation flags write their own params.
func TestSourceOptionsBrokenParamIsAnError(t *testing.T) {
	t.Parallel()

	shared := &sharedOptions{}
	shared.Raw = []string{"broken"}
	opts := &sourceOptions{
		shared:          shared,
		ExpectedBranch:  "main",
		ExpectedRepo:    "https://github.com/example/repo",
		Since:           "2025-01-01",
		AttestationPath: filepath.Join("..", "..", "pkg", "slsa", "testdata", "plain", "source.intoto.json"),
	}
	err := opts.Validate()
	require.ErrorContains(t, err, `invalid param "broken"`)
	// The flag-derived params still landed, so the error report is
	// the only thing wrong with this invocation.
	assert.Equal(t, "main", opts.shared.Params["expected_branch"])
	assert.Equal(t, "https://github.com/example/repo", opts.shared.Params["expected_source_repo"])
	assert.Equal(t, "2025-01-01T00:00:00Z", opts.shared.Params["enforced_since"])
}

func TestSourceOptionsSubject(t *testing.T) {
	t.Parallel()
	fixture := filepath.Join("..", "..", "pkg", "slsa", "testdata", "plain", "source.intoto.json")
	sha := strings.Repeat("ab", 20)

	newOpts := func(spec, arg string) *sourceOptions {
		return &sourceOptions{shared: &sharedOptions{}, Level: "1", AttestationPath: fixture, SubjectSpec: spec, SubjectArg: arg}
	}

	// Nothing given: unbound.
	opts := newOpts("", "")
	require.NoError(t, opts.Validate())
	assert.Nil(t, opts.Subject)
	assert.Nil(t, opts.subjects())

	// --subject as algorithm:digest.
	opts = newOpts("gitCommit:"+sha, "")
	require.NoError(t, opts.Validate())
	require.NotNil(t, opts.Subject)
	assert.Equal(t, map[string]string{"gitCommit": sha}, opts.Subject.Digests)
	require.Len(t, opts.subjects(), 1)

	// Positional bare sha is taken as a gitCommit.
	opts = newOpts("", sha)
	require.NoError(t, opts.Validate())
	require.NotNil(t, opts.Subject)
	assert.Equal(t, map[string]string{"gitCommit": sha}, opts.Subject.Digests)

	// Positional algorithm:digest, any algorithm.
	opts = newOpts("", "sha256:"+strings.Repeat("cd", 32))
	require.NoError(t, opts.Validate())
	assert.Equal(t, map[string]string{"sha256": strings.Repeat("cd", 32)}, opts.Subject.Digests)

	// Both is an error, as is anything that is neither form.
	require.ErrorContains(t, newOpts("gitCommit:"+sha, sha).Validate(), "not both")
	require.ErrorContains(t, newOpts("", "abc123").Validate(), "40-character commit sha")
	require.ErrorContains(t, newOpts("gitCommit:zz", "").Validate(), "not hex")
}

// TestRunSourceSubject binds the source attestation to the commit the
// user names.
func TestRunSourceSubject(t *testing.T) {
	t.Parallel()
	sha := "3ede92d1d86076be3e238618b5a54c8189668e3f"

	// A copy of the source fixture about a real-length commit.
	raw, err := os.ReadFile(filepath.Join("..", "..", "pkg", "slsa", "testdata", "plain", "source.intoto.json"))
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	doc["subject"] = []any{map[string]any{"digest": map[string]any{"gitCommit": sha}}}
	data, err := json.Marshal(doc)
	require.NoError(t, err)
	fixture := filepath.Join(t.TempDir(), "source.intoto.json")
	require.NoError(t, os.WriteFile(fixture, data, 0o600))

	for _, tc := range []struct {
		name       string
		spec, arg  string
		aliases    bool
		wantPass   bool
		wantOutput []string
	}{
		{name: "unbound", wantPass: true},
		{name: "commit via --subject", spec: "gitCommit:" + sha, wantPass: true, wantOutput: []string{"Subjects:", "[PASS]", "gitCommit:" + sha[:16]}},
		{name: "commit via positional bare sha", arg: sha, wantPass: true, wantOutput: []string{"[PASS]"}},
		{name: "another commit fails", arg: strings.Repeat("00", 20), wantPass: false, wantOutput: []string{"[FAIL]", "does not match", "1 of 1 expected subjects not found"}},
		// A sha1 is the same hash as the gitCommit, but only with aliases on.
		{name: "sha1 without aliases", spec: "sha1:" + sha, wantPass: false, wantOutput: []string{"[FAIL]", "no comparable digest", "gitCommit"}},
		{name: "sha1 with aliases", spec: "sha1:" + sha, aliases: true, wantPass: true, wantOutput: []string{"[PASS]"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := &sourceOptions{
				shared:          &sharedOptions{GitDigestAliases: tc.aliases},
				Level:           "1",
				ExpectedRepo:    "https://github.com/example/repo",
				ExpectedBranch:  "refs/heads/main",
				AttestationPath: fixture,
				SubjectSpec:     tc.spec,
				SubjectArg:      tc.arg,
			}
			require.NoError(t, opts.Validate())

			var out bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetOut(&out)
			err := runSource(cmd, opts)
			for _, want := range tc.wantOutput {
				assert.Contains(t, out.String(), want)
			}
			if tc.wantPass {
				require.NoError(t, err)
				assert.True(t, strings.HasPrefix(out.String(), "PASS"), out.String())
				return
			}
			require.ErrorIs(t, err, ErrVerifyFailed)
			assert.True(t, strings.HasPrefix(out.String(), "FAIL"), out.String())
		})
	}
}

// The git digest aliases flag is on unless switched off.
func TestSharedOptionsGitDigestAliasesDefaultOn(t *testing.T) {
	t.Parallel()
	shared := &sharedOptions{}
	shared.AddFlags(&cobra.Command{})
	assert.True(t, shared.GitDigestAliases)
}
