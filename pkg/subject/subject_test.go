// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package subject

import (
	"crypto/sha256"
	"crypto/sha512"
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

func rd(digests map[string]string) attestation.Subject {
	return &intoto.ResourceDescriptor{Name: "artifact", Digest: digests}
}

func TestParse(t *testing.T) {
	t.Parallel()
	sha := strings.Repeat("ab", 32)

	e, err := Parse("sha256:" + strings.ToUpper(sha))
	require.NoError(t, err)
	assert.Equal(t, "sha256:"+sha, e.Name, "the digest is normalized to lower case")
	assert.Equal(t, map[string]string{"sha256": sha}, e.Digests)

	e, err = Parse("gitCommit:" + strings.Repeat("0", 40))
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"gitCommit": strings.Repeat("0", 40)}, e.Digests)

	for _, bad := range []string{
		"", "sha256", ":abc", "sha256:", "md6:" + sha, "sha256:xyz", "sha256:" + sha[:10],
	} {
		_, err := Parse(bad)
		require.Error(t, err, bad)
	}
	_, err = Parse("md6:" + sha)
	require.ErrorContains(t, err, "unknown digest algorithm")
	_, err = Parse("sha256:" + sha[:10])
	require.ErrorContains(t, err, "64 hex characters")
}

func TestAlgorithms(t *testing.T) {
	t.Parallel()
	subjects := []attestation.Subject{
		rd(map[string]string{"sha256": "a", "gitCommit": "b"}),
		rd(map[string]string{"sha512": "c", "sha256": "d", "blake2b": "e"}),
		nil,
	}
	hashable, other := Algorithms(subjects)
	assert.Equal(t, []intoto.HashAlgorithm{intoto.AlgorithmSHA256, intoto.AlgorithmSHA512}, hashable)
	assert.Equal(t, []string{"blake2b", "gitCommit"}, other)

	hashable, other = Algorithms(nil)
	assert.Empty(t, hashable)
	assert.Empty(t, other)
}

func TestHashFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	a := filepath.Join(dir, "a.bin")
	b := filepath.Join(dir, "b.bin")
	require.NoError(t, os.WriteFile(a, []byte("artifact a"), 0o600))
	require.NoError(t, os.WriteFile(b, []byte("artifact b"), 0o600))

	got, err := HashFiles([]string{a, b}, []intoto.HashAlgorithm{intoto.AlgorithmSHA256, intoto.AlgorithmSHA512})
	require.NoError(t, err)
	require.Len(t, got, 2)

	sumA256 := sha256.Sum256([]byte("artifact a"))
	sumB512 := sha512.Sum512([]byte("artifact b"))
	assert.Equal(t, a, got[0].Name)
	assert.Equal(t, hex.EncodeToString(sumA256[:]), got[0].Digests["sha256"])
	assert.Equal(t, b, got[1].Name)
	assert.Equal(t, hex.EncodeToString(sumB512[:]), got[1].Digests["sha512"])
	assert.Len(t, got[1].Digests, 2)

	// Nothing to hash is not an error; no algorithm to hash with is.
	got, err = HashFiles(nil, nil)
	require.NoError(t, err)
	assert.Nil(t, got)
	_, err = HashFiles([]string{a}, nil)
	require.Error(t, err)
	_, err = HashFiles([]string{filepath.Join(dir, "missing")}, []intoto.HashAlgorithm{intoto.AlgorithmSHA256})
	require.Error(t, err)
}

func TestMatchAll(t *testing.T) {
	t.Parallel()
	subjects := []attestation.Subject{
		rd(map[string]string{"sha256": "aaaa", "sha512": "bbbb"}),
		rd(map[string]string{"gitCommit": "cccc"}),
	}
	expect := func(digests map[string]string) *Expected {
		return &Expected{Name: "x", Digests: digests}
	}

	for _, tc := range []struct {
		name     string
		expected *Expected
		subjects []attestation.Subject
		matched  bool
		message  string
	}{
		{"one common algorithm agrees", expect(map[string]string{"sha256": "aaaa"}), subjects, true, ""},
		{"all common algorithms agree", expect(map[string]string{"sha256": "aaaa", "sha512": "bbbb"}), subjects, true, ""},
		{"extra algorithm on the expected side is fine", expect(map[string]string{"sha256": "aaaa", "sha1": "zzzz"}), subjects, true, ""},
		{"a common algorithm disagrees", expect(map[string]string{"sha256": "aaaa", "sha512": "wrong"}), subjects, false, "does not match"},
		{"wrong digest", expect(map[string]string{"sha256": "ffff"}), subjects, false, "does not match"},
		{"no comparable digest", expect(map[string]string{"sha1": "ffff"}), subjects, false, "subjects use gitCommit, sha256, sha512"},
		{"no subjects at all", expect(map[string]string{"sha256": "aaaa"}), nil, false, "no subjects"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			matches := MatchAll([]*Expected{tc.expected}, tc.subjects)
			require.Len(t, matches, 1)
			m := matches[0]
			assert.Equal(t, tc.matched, m.Matched)
			assert.Same(t, tc.expected, m.Expected)
			if tc.matched {
				assert.NotNil(t, m.Subject)
				assert.Empty(t, m.Message)
			} else {
				assert.Nil(t, m.Subject)
				assert.Contains(t, m.Message, tc.message)
			}
			assert.Equal(t, tc.matched, AllMatched(matches))
		})
	}

	// One failing subject fails the set; an empty set is trivially matched.
	matches := MatchAll([]*Expected{expect(map[string]string{"sha256": "aaaa"}), expect(map[string]string{"sha256": "ffff"})}, subjects)
	assert.False(t, AllMatched(matches))
	assert.True(t, matches[0].Matched)
	assert.False(t, matches[1].Matched)
	assert.True(t, AllMatched(nil))
}

// Git digest aliases are on by default.
func TestMatchAllGitDigestAliasesDefaultOn(t *testing.T) {
	t.Parallel()
	sha1 := strings.Repeat("ab", 20)
	matches := MatchAll([]*Expected{{Name: "x", Digests: map[string]string{"sha1": sha1}}},
		[]attestation.Subject{rd(map[string]string{"gitCommit": sha1})})
	require.Len(t, matches, 1)
	assert.True(t, matches[0].Matched)
}

// With git digest aliases, a git object digest and the hash it is meet
// in either direction; without them they are different algorithms.
func TestMatchAllGitDigestAliases(t *testing.T) {
	t.Parallel()
	sha1 := strings.Repeat("ab", 20)
	digest256 := strings.Repeat("cd", 32)
	commit := []attestation.Subject{rd(map[string]string{"gitCommit": sha1})}
	commit256 := []attestation.Subject{rd(map[string]string{"gitCommit": digest256})}
	plainSHA1 := []attestation.Subject{rd(map[string]string{"sha1": sha1})}

	for _, tc := range []struct {
		name     string
		expected map[string]string
		subjects []attestation.Subject
		aliases  bool
		matched  bool
	}{
		{"sha1 meets gitCommit", map[string]string{"sha1": sha1}, commit, true, true},
		{"gitCommit meets sha1", map[string]string{"gitCommit": sha1}, plainSHA1, true, true},
		{"sha256 meets a sha256-repo gitCommit", map[string]string{"sha256": digest256}, commit256, true, true},
		{"gitTree meets gitCommit of the same hash", map[string]string{"gitTree": sha1}, commit, true, true},
		{"different sha1 still fails", map[string]string{"sha1": strings.Repeat("ef", 20)}, commit, true, false},
		{"without aliases sha1 and gitCommit are unrelated", map[string]string{"sha1": sha1}, commit, false, false},
		{"without aliases gitCommit and sha1 are unrelated", map[string]string{"gitCommit": sha1}, plainSHA1, false, false},
		// A stated algorithm is never overridden by an alias: the
		// subject says sha1 is something else, so they disagree.
		{
			name:     "stated sha1 wins over the alias",
			expected: map[string]string{"sha1": sha1},
			subjects: []attestation.Subject{rd(map[string]string{"gitCommit": sha1, "sha1": strings.Repeat("ef", 20)})},
			aliases:  true,
			matched:  false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			matches := MatchAll([]*Expected{{Name: "x", Digests: tc.expected}}, tc.subjects, WithGitDigestAliases(tc.aliases))
			require.Len(t, matches, 1)
			assert.Equal(t, tc.matched, matches[0].Matched, matches[0].Message)
			if tc.matched {
				assert.Same(t, tc.subjects[0], matches[0].Subject, "the original subject is reported, not the aliased view")
			}
		})
	}
}
