// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/verifier/pkg/slsa/vsa"
)

func TestLoadParsesVSAFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "vsa.intoto.json")
	require.NoError(t, os.WriteFile(path, []byte(`{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"name": "pkg:oci/foo@sha256:abc", "digest": {"sha256": "abc"}}],
  "predicateType": "https://slsa.dev/verification_summary/v1",
  "predicate": {
    "verifier": {"id": "https://verify.example.com"},
    "verificationResult": "PASSED",
    "verifiedLevels": ["SLSA_BUILD_LEVEL_3"]
  }
}`), 0o600))

	env, err := New().Load(path)
	require.NoError(t, err)
	require.NotNil(t, env)
	assert.Equal(t, vsa.PredicateTypeV1, string(env.GetStatement().GetPredicateType()))
}

func TestLoadMissingFile(t *testing.T) {
	t.Parallel()

	_, err := New().Load("/nonexistent/path/vsa.json")
	require.Error(t, err)
}
