// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
	"context"
	"testing"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/verifier/pkg/subject"
)

type subjectsStatement struct {
	attestation.Statement
	subjects []attestation.Subject
}

func (s *subjectsStatement) GetSubjects() []attestation.Subject { return s.subjects }

func TestCheckSubjects(t *testing.T) {
	t.Parallel()
	impl := &defaultImplementation{}
	stmt := &subjectsStatement{subjects: []attestation.Subject{
		&intoto.ResourceDescriptor{Name: "out/binary", Digest: map[string]string{"sha256": "aaaa"}},
	}}
	good := &subject.Expected{Name: "binary", Digests: map[string]string{"sha256": "aaaa"}}
	bad := &subject.Expected{Name: "other", Digests: map[string]string{"sha256": "ffff"}}

	// Nothing expected: nothing checked, no error.
	matches, err := impl.CheckSubjects(context.Background(), &VerificationOptions{}, stmt)
	require.NoError(t, err)
	assert.Empty(t, matches)
	matches, err = impl.CheckSubjects(context.Background(), nil, stmt)
	require.NoError(t, err)
	assert.Empty(t, matches)

	// One match per expected subject, in order; mismatches are not errors.
	matches, err = impl.CheckSubjects(context.Background(), &VerificationOptions{Subjects: []*subject.Expected{good, bad}}, stmt)
	require.NoError(t, err)
	require.Len(t, matches, 2)
	assert.True(t, matches[0].Matched)
	assert.Same(t, matches[0].Expected, good)
	assert.False(t, matches[1].Matched)
	assert.Same(t, matches[1].Expected, bad)
	assert.NotEmpty(t, matches[1].Message)

	// A statement is required once there is something to check.
	_, err = impl.CheckSubjects(context.Background(), &VerificationOptions{Subjects: []*subject.Expected{good}}, nil)
	require.Error(t, err)
}
