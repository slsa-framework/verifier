// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package subject binds the artifacts a caller holds to the subjects an
// attestation is about. An Expected subject comes from a digest the
// caller states (algo:digest) or from hashing a file with the algorithms
// the attestation's subjects use; MatchAll then reports, per expected
// subject, whether the attestation covers it.
package subject

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/carabiner-dev/hasher"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
)

// Expected is an artifact the caller holds, identified by its digests.
// It implements attestation.Subject so it can be compared with the
// subjects of a statement directly.
type Expected struct {
	// Name is how the artifact is reported back: the file path it was
	// hashed from, or the algo:digest spec it was given as.
	Name string

	// Digests holds the artifact's digests keyed by in-toto algorithm
	// name (sha256, sha512, gitCommit, …).
	Digests map[string]string
}

func (e *Expected) GetName() string              { return e.Name }
func (e *Expected) GetUri() string               { return "" }
func (e *Expected) GetDigest() map[string]string { return e.Digests }

// Parse parses an expected subject given as algo:digest, for example
// sha256:83476843…. The algorithm must be one in-toto defines and the
// digest must be hex of the algorithm's length. The digest is
// normalized to lower case.
func Parse(spec string) (*Expected, error) {
	algoName, digest, ok := strings.Cut(strings.TrimSpace(spec), ":")
	if !ok || algoName == "" || digest == "" {
		return nil, fmt.Errorf("invalid subject %q: want algorithm:digest, e.g. sha256:<hex>", spec)
	}
	algo, ok := intoto.HashAlgorithms[algoName]
	if !ok {
		return nil, fmt.Errorf("invalid subject %q: unknown digest algorithm %q (want one of %s)", spec, algoName, knownAlgorithms())
	}
	digest = strings.ToLower(digest)
	if _, err := hex.DecodeString(digest); err != nil {
		return nil, fmt.Errorf("invalid subject %q: digest is not hex: %w", spec, err)
	}
	if want := algo.HexLength() * 2; want > 0 && len(digest) != want {
		return nil, fmt.Errorf("invalid subject %q: %s digests are %d hex characters, got %d", spec, algo, want, len(digest))
	}
	return &Expected{Name: string(algo) + ":" + digest, Digests: map[string]string{string(algo): digest}}, nil
}

func knownAlgorithms() string {
	names := make([]string, 0, len(intoto.HashAlgorithms))
	for name := range intoto.HashAlgorithms {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// Algorithms returns the digest algorithms the subjects use, split into
// those files can be hashed with and those that cannot (gitCommit,
// dirHash and other digests that are not a hash of the file contents,
// or algorithms the hasher does not implement). Both lists are sorted
// and de-duplicated.
func Algorithms(subjects []attestation.Subject) (hashable []intoto.HashAlgorithm, other []string) {
	seen := map[string]bool{}
	for _, s := range subjects {
		if s == nil {
			continue
		}
		for name := range s.GetDigest() {
			if seen[name] {
				continue
			}
			seen[name] = true
			algo := intoto.HashAlgorithm(name)
			if _, ok := hasher.HasherFactory[algo]; ok && isContentHash(algo) {
				hashable = append(hashable, algo)
			} else {
				other = append(other, name)
			}
		}
	}
	slices.Sort(hashable)
	sort.Strings(other)
	return hashable, other
}

// isContentHash reports whether an algorithm digests the raw contents of
// a file. The git and directory digests hash a typed object, so hashing
// a file with them would not produce the value an attestation carries.
func isContentHash(algo intoto.HashAlgorithm) bool {
	//nolint:exhaustive // every other algorithm digests the file contents
	switch algo {
	case intoto.AlgorithmGitBlob, intoto.AlgorithmGitCommit, intoto.AlgorithmGitTag, intoto.AlgorithmGitTree, intoto.AlgorithmDirHash:
		return false
	default:
		return true
	}
}

// HashFiles hashes each path with every algorithm given, in parallel,
// and returns one Expected per path in the same order, named by path.
func HashFiles(paths []string, algos []intoto.HashAlgorithm) ([]*Expected, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	if len(algos) == 0 {
		return nil, errors.New("no digest algorithm to hash the files with")
	}
	h := hasher.New()
	if err := hasher.WithAlgorithms(algos)(&h.Options); err != nil {
		return nil, err
	}
	sets, err := h.HashFiles(paths)
	if err != nil {
		return nil, fmt.Errorf("hashing files: %w", err)
	}
	out := make([]*Expected, 0, len(paths))
	for _, path := range paths {
		set, ok := (*sets)[path]
		if !ok {
			return nil, fmt.Errorf("hashing files: no digests returned for %s", path)
		}
		digests := make(map[string]string, len(set))
		for algo, digest := range set {
			digests[string(algo)] = digest
		}
		out = append(out, &Expected{Name: path, Digests: digests})
	}
	return out, nil
}

// Match is the outcome of looking for one expected subject among an
// attestation's subjects.
type Match struct {
	// Expected is the subject the caller asked about.
	Expected *Expected

	// Subject is the attestation subject it matched, nil when none did.
	Subject attestation.Subject

	// Matched reports whether an attestation subject covers Expected:
	// the two share at least one digest algorithm and agree on every
	// algorithm they share.
	Matched bool

	// Message says why there was no match. Empty when Matched.
	Message string
}

// MatchOption tunes how expected subjects are compared with the
// attestation's.
type MatchOption func(*matchOptions)

type matchOptions struct {
	gitDigestAliases bool
}

// WithGitDigestAliases controls whether the git object digests (gitCommit,
// gitTree, gitBlob, gitTag) are interchangeable with the hash they are: a
// 40-character git digest is also a sha1 digest and a 64-character one is
// also a sha256 digest, on both sides of the comparison, so sha1:<sha>
// matches an attestation subject carrying gitCommit:<sha> and the other
// way around. An algorithm a subject already states is never overridden.
// On by default; pass false to require the exact algorithm names.
func WithGitDigestAliases(enabled bool) MatchOption {
	return func(o *matchOptions) { o.gitDigestAliases = enabled }
}

// MatchAll looks for every expected subject among subjects and reports
// each outcome in order. Matching follows attestation.SubjectsMatch:
// a subject matches when it shares at least one digest algorithm with
// the expected subject and every shared digest is equal.
func MatchAll(expected []*Expected, subjects []attestation.Subject, opts ...MatchOption) []Match {
	o := matchOptions{gitDigestAliases: true}
	for _, fn := range opts {
		fn(&o)
	}
	out := make([]Match, 0, len(expected))
	for _, e := range expected {
		out = append(out, matchOne(e, subjects, &o))
	}
	return out
}

// gitDigestAliases returns a copy of digests where every git object
// digest is also present under the hash algorithm it is (sha1 or
// sha256, by length), unless that algorithm is already stated.
func gitDigestAliases(digests map[string]string) map[string]string {
	out := make(map[string]string, len(digests)+2)
	for algo, digest := range digests {
		out[algo] = digest
	}
	for algo, digest := range digests {
		if isContentHash(intoto.HashAlgorithm(algo)) || algo == string(intoto.AlgorithmDirHash) {
			continue
		}
		var hash intoto.HashAlgorithm
		switch len(digest) {
		case 2 * intoto.AlgorithmSHA1.HexLength():
			hash = intoto.AlgorithmSHA1
		case 2 * intoto.AlgorithmSHA256.HexLength():
			hash = intoto.AlgorithmSHA256
		default:
			continue
		}
		if _, stated := out[string(hash)]; !stated {
			out[string(hash)] = digest
		}
	}
	return out
}

// aliased wraps an attestation subject with git digest aliases applied
// for comparison; the original subject is what gets reported.
type aliased struct {
	attestation.Subject
	digests map[string]string
}

func (a *aliased) GetDigest() map[string]string { return a.digests }

func matchOne(e *Expected, subjects []attestation.Subject, o *matchOptions) Match {
	m := Match{Expected: e}
	if len(subjects) == 0 {
		m.Message = "the attestation has no subjects"
		return m
	}
	want := e
	if o.gitDigestAliases {
		want = &Expected{Name: e.Name, Digests: gitDigestAliases(e.Digests)}
	}
	sharesAlgorithm := false
	for _, s := range subjects {
		if s == nil {
			continue
		}
		got := s
		if o.gitDigestAliases {
			got = &aliased{Subject: s, digests: gitDigestAliases(s.GetDigest())}
		}
		if attestation.SubjectsMatch(want, got) {
			m.Matched = true
			m.Subject = s
			return m
		}
		for algo := range want.GetDigest() {
			if _, ok := got.GetDigest()[algo]; ok {
				sharesAlgorithm = true
			}
		}
	}
	if sharesAlgorithm {
		m.Message = "digest does not match any attestation subject"
		return m
	}
	var carried []string
	seen := map[string]bool{}
	for _, s := range subjects {
		if s == nil {
			continue
		}
		for algo := range s.GetDigest() {
			if !seen[algo] {
				seen[algo] = true
				carried = append(carried, algo)
			}
		}
	}
	sort.Strings(carried)
	m.Message = fmt.Sprintf("no comparable digest: the attestation subjects use %s", strings.Join(carried, ", "))
	return m
}

// AllMatched reports whether every match succeeded. An empty list is
// trivially matched: nothing was asked.
func AllMatched(matches []Match) bool {
	for _, m := range matches {
		if !m.Matched {
			return false
		}
	}
	return true
}
