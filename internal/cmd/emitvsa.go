// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"io"
	"time"

	intoto "github.com/in-toto/attestation/go/v1"
	cdattestation "github.com/policylabs/attestation"

	"github.com/slsa-framework/verifier/pkg/slsa"
	"github.com/slsa-framework/verifier/pkg/slsa/controls"
	"github.com/slsa-framework/verifier/pkg/slsa/vsa"
	"github.com/slsa-framework/verifier/pkg/subject"
)

// emitVSA writes an unsigned VSA v1 statement describing result to w. The
// statement records the overall PASSED/FAILED outcome, the computed SLSA
// level (as verifiedLevels for the given track) when the run passed, and
// the subjects of the verified attestation. It is the shared output path
// for the build and source verifiers when their --vsa flag is set.
func emitVSA(w io.Writer, stmt cdattestation.Statement, result *slsa.Result, track controls.Track) error {
	subjects := vsaSubjects(stmt)
	// When the run was bound to specific artifacts, the summary is
	// about those: the attestation subjects they matched.
	if len(result.Subjects) > 0 {
		subjects = matchedSubjects(result.Subjects)
	}
	// Prefer the identity carried on the result (set through
	// WithVerifierID) or fall back to this tool's own ID when
	// a caller ran the verification without supplying one.
	id := result.VerifierID
	if id == "" {
		id = defaultVerifierID
	}
	in := vsa.SummaryInput{
		VerifierID:         id,
		TimeVerified:       time.Now(),
		Subjects:           subjects,
		VerificationResult: vsaResult(result),
		VerifiedLevels:     verifiedLevels(track, result),
		SLSAVersion:        result.SpecVersion,
	}
	// Use the first subject's URI as the resource the VSA covers, when one
	// is available.
	if len(subjects) > 0 {
		in.ResourceURI = subjects[0].GetUri()
	}

	statement, err := in.Statement()
	if err != nil {
		return err
	}
	data, err := vsa.Marshal(statement)
	if err != nil {
		return err
	}
	writef(w, "%s\n", data)
	return nil
}

// vsaResult maps a verification Result onto the VSA verificationResult
// vocabulary.
func vsaResult(result *slsa.Result) string {
	if result.Pass() {
		return vsa.ResultPassed
	}
	return vsa.ResultFailed
}

// verifiedLevels renders the computed SLSA level as the canonical
// verifiedLevels entry for the track, eg SLSA_BUILD_LEVEL_3. A failed
// run yields an empty list whatever level its core controls reached:
// verifiedLevels is what the verifier vouches for, and consumers read
// it on its own, so a FAILED summary must not carry a level a policy
// could accept. A non-positive level (nothing established) is empty
// too.
func verifiedLevels(track controls.Track, result *slsa.Result) []string {
	if !result.Pass() || result.SLSALevel <= 0 {
		return nil
	}
	level := result.SLSALevel
	prefix := "SLSA_BUILD_LEVEL_"
	if track == controls.TrackSource {
		prefix = "SLSA_SOURCE_LEVEL_"
	}
	return []string{fmt.Sprintf("%s%d", prefix, level)}
}

// matchedSubjects projects the attestation subjects the expected
// artifacts matched onto the VSA subject type, de-duplicated and in
// order of first match.
func matchedSubjects(matches []subject.Match) []*intoto.ResourceDescriptor {
	out := []*intoto.ResourceDescriptor{}
	seen := map[cdattestation.Subject]bool{}
	for _, m := range matches {
		if !m.Matched || m.Subject == nil || seen[m.Subject] {
			continue
		}
		seen[m.Subject] = true
		out = append(out, &intoto.ResourceDescriptor{
			Name:   m.Subject.GetName(),
			Uri:    m.Subject.GetUri(),
			Digest: m.Subject.GetDigest(),
		})
	}
	return out
}

// vsaSubjects projects the verified statement's subjects onto the
// concrete in-toto ResourceDescriptor type the VSA statement carries.
func vsaSubjects(stmt cdattestation.Statement) []*intoto.ResourceDescriptor {
	if stmt == nil {
		return nil
	}
	subs := stmt.GetSubjects()
	out := make([]*intoto.ResourceDescriptor, 0, len(subs))
	for _, s := range subs {
		if s == nil {
			continue
		}
		out = append(out, &intoto.ResourceDescriptor{
			Name:   s.GetName(),
			Uri:    s.GetUri(),
			Digest: s.GetDigest(),
		})
	}
	return out
}
