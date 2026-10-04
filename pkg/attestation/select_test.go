// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"testing"

	intoto "github.com/in-toto/attestation/go/v1"
	cdattestation "github.com/policylabs/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/verifier/pkg/subject"
)

const (
	sourceProv = "https://github.com/slsa-framework/source-tool/source-provenance/v1"
	tagProv    = "https://github.com/slsa-framework/source-tool/tag-provenance/v1"
	vsaV1      = "https://slsa.dev/verification_summary/v1"
	commitA    = "1824b8fb8980a7fae36eb325408d35c344c04fd9"
	commitB    = "b797d53cd7fe550be0dcddb05594343dce3e4cc5"
)

// otherSignature is a second distinct signature for duplicate tests.
type otherSignature struct{}

func (otherSignature) GetKeyid() string { return "other-keyid" }
func (otherSignature) GetSig() []byte   { return []byte("other") }

func envAbout(pType, commit string) Envelope {
	return &fakeEnvelope{stmt: &fakeStmt{
		pType:    cdattestation.PredicateType(pType),
		subjects: []cdattestation.Subject{&intoto.ResourceDescriptor{Digest: map[string]string{"gitCommit": commit}}},
	}}
}

func TestSelect(t *testing.T) {
	t.Parallel()
	commitASubject, err := subject.Parse("gitCommit:" + commitA)
	require.NoError(t, err)
	commitBSubject, err := subject.Parse("sha1:" + commitB)
	require.NoError(t, err)

	note := []Envelope{envAbout(sourceProv, commitA), envAbout(vsaV1, commitA), envAbout(tagProv, commitA)}

	t.Run("a single envelope is taken as is", func(t *testing.T) {
		t.Parallel()
		env, err := Select([]Envelope{envAbout(vsaV1, commitA)}, &Selection{PredicateTypes: []string{sourceProv}})
		require.NoError(t, err)
		assert.Equal(t, vsaV1, string(env.GetStatement().GetPredicateType()))
	})
	t.Run("nothing to select from", func(t *testing.T) {
		t.Parallel()
		_, err := Select(nil, &Selection{Kind: "VSA"})
		require.ErrorIs(t, err, ErrNoApplicableAttestation)
	})
	t.Run("by predicate type", func(t *testing.T) {
		t.Parallel()
		env, err := Select(note, &Selection{Kind: "VSA", PredicateTypes: []string{vsaV1}})
		require.NoError(t, err)
		assert.Equal(t, vsaV1, string(env.GetStatement().GetPredicateType()))
	})
	t.Run("none of the type", func(t *testing.T) {
		t.Parallel()
		_, err := Select(note, &Selection{Kind: "build provenance", PredicateTypes: []string{"https://slsa.dev/provenance/v1"}})
		require.ErrorIs(t, err, ErrNoApplicableAttestation)
		assert.Contains(t, err.Error(), "none of the 3 attestations in the file is a build provenance")
		assert.Contains(t, err.Error(), sourceProv)
	})
	t.Run("preference breaks a tie", func(t *testing.T) {
		t.Parallel()
		types := []string{sourceProv, tagProv}
		env, err := Select(note, &Selection{PredicateTypes: types, Prefer: []string{sourceProv, tagProv}})
		require.NoError(t, err)
		assert.Equal(t, sourceProv, string(env.GetStatement().GetPredicateType()))
		env, err = Select(note, &Selection{PredicateTypes: types, Prefer: []string{tagProv, sourceProv}})
		require.NoError(t, err)
		assert.Equal(t, tagProv, string(env.GetStatement().GetPredicateType()))
	})
	t.Run("ambiguous without a preference", func(t *testing.T) {
		t.Parallel()
		_, err := Select(note, &Selection{Kind: "source attestation", PredicateTypes: []string{sourceProv, tagProv}})
		require.ErrorIs(t, err, ErrAmbiguousAttestation)
		assert.Contains(t, err.Error(), "2 of the 3 attestations")
	})
	t.Run("by subject, with git digest aliases", func(t *testing.T) {
		t.Parallel()
		envs := []Envelope{envAbout(sourceProv, commitA), envAbout(sourceProv, commitB)}
		env, err := Select(envs, &Selection{PredicateTypes: []string{sourceProv}, Subjects: []*subject.Expected{commitBSubject}})
		require.NoError(t, err)
		assert.Equal(t, commitB, env.GetStatement().GetSubjects()[0].GetDigest()["gitCommit"])
		_, err = Select(envs, &Selection{PredicateTypes: []string{sourceProv}, Subjects: []*subject.Expected{commitBSubject}, NoGitDigestAliases: true})
		require.ErrorIs(t, err, ErrNoApplicableAttestation, "sha1 does not match gitCommit without aliases")
		env, err = Select(envs, &Selection{PredicateTypes: []string{sourceProv}, Subjects: []*subject.Expected{commitASubject}})
		require.NoError(t, err)
		assert.Equal(t, commitA, env.GetStatement().GetSubjects()[0].GetDigest()["gitCommit"])
	})
	t.Run("exact duplicates are one attestation", func(t *testing.T) {
		t.Parallel()
		signed := func() Envelope {
			return &fakeEnvelope{stmt: envAbout(sourceProv, commitA).GetStatement(), sigs: oneSig}
		}
		env, err := Select([]Envelope{signed(), envAbout(vsaV1, commitA), signed()}, &Selection{PredicateTypes: []string{sourceProv}})
		require.NoError(t, err)
		assert.Equal(t, sourceProv, string(env.GetStatement().GetPredicateType()))
		// The same statement under another signature is another attestation.
		other := &fakeEnvelope{stmt: envAbout(sourceProv, commitA).GetStatement(), sigs: []cdattestation.Signature{otherSignature{}}}
		_, err = Select([]Envelope{signed(), other}, &Selection{PredicateTypes: []string{sourceProv}})
		require.ErrorIs(t, err, ErrAmbiguousAttestation)
	})
	t.Run("envelopes without a statement are skipped", func(t *testing.T) {
		t.Parallel()
		env, err := Select([]Envelope{&fakeEnvelope{}, envAbout(vsaV1, commitA)}, &Selection{PredicateTypes: []string{vsaV1}})
		require.NoError(t, err)
		assert.NotNil(t, env.GetStatement())
	})
}
