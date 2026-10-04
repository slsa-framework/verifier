// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stmtWithSubjects struct {
	attestation.Statement
	subjects []attestation.Subject
}

func (s *stmtWithSubjects) GetSubjects() []attestation.Subject { return s.subjects }

func TestSubjectOptionsValidate(t *testing.T) {
	t.Parallel()
	sha := strings.Repeat("ab", 32)
	dir := t.TempDir()
	file := filepath.Join(dir, "artifact")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))

	o := &subjectOptions{SubjectSpecs: []string{"sha256:" + sha}, ArtifactPaths: []string{file}}
	require.NoError(t, o.Validate())
	require.Len(t, o.Subjects, 1)
	assert.Equal(t, sha, o.Subjects[0].Digests["sha256"])
	assert.True(t, o.expects())

	o = &subjectOptions{SubjectSpecs: []string{"nope"}, ArtifactPaths: []string{filepath.Join(dir, "missing"), dir}}
	err := o.Validate()
	require.ErrorContains(t, err, `invalid subject "nope"`)
	require.ErrorContains(t, err, "missing")
	require.ErrorContains(t, err, "is a directory")

	assert.False(t, (&subjectOptions{}).expects())
}

func TestSubjectOptionsResolve(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	file := filepath.Join(dir, "artifact.tgz")
	content := []byte("the artifact")
	require.NoError(t, os.WriteFile(file, content, 0o600))
	sum := sha256.Sum256(content)
	sha := strings.Repeat("cd", 32)

	stmt := &stmtWithSubjects{subjects: []attestation.Subject{
		&intoto.ResourceDescriptor{Name: "a", Digest: map[string]string{"sha256": "aaaa", "gitCommit": "bbbb"}},
	}}

	// Nothing asked: nothing resolved.
	got, err := (&subjectOptions{}).resolve(stmt)
	require.NoError(t, err)
	assert.Nil(t, got)

	// Files are hashed with the hashable algorithms the subjects use,
	// then the --subject values follow in order.
	o := &subjectOptions{SubjectSpecs: []string{"sha256:" + sha}, ArtifactPaths: []string{file}}
	require.NoError(t, o.Validate())
	got, err = o.resolve(stmt)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, file, got[0].Name)
	assert.Equal(t, map[string]string{"sha256": hex.EncodeToString(sum[:])}, got[0].Digests, "only the subjects' hashable algorithms are computed")
	assert.Equal(t, sha, got[1].Digests["sha256"])

	// Files cannot be checked against subjects without content digests.
	gitOnly := &stmtWithSubjects{subjects: []attestation.Subject{
		&intoto.ResourceDescriptor{Name: "a", Digest: map[string]string{"gitCommit": "bbbb"}},
	}}
	_, err = o.resolve(gitOnly)
	require.ErrorContains(t, err, "gitCommit")
	require.ErrorContains(t, err, "--subject")

	// A digest-only expectation is fine against any statement.
	specOnly := &subjectOptions{SubjectSpecs: []string{"gitCommit:" + strings.Repeat("0", 40)}}
	require.NoError(t, specOnly.Validate())
	got, err = specOnly.resolve(gitOnly)
	require.NoError(t, err)
	require.Len(t, got, 1)
}
