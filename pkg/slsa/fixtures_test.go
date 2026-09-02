// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package slsa_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector/envelope"
	provenancev01 "github.com/in-toto/attestation/go/predicates/provenance/v01"
	provenancev02 "github.com/in-toto/attestation/go/predicates/provenance/v02"
	provenancev1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	sourceprovenance "github.com/slsa-framework/source-tool/pkg/provenance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/slsa-framework/verifier/pkg/slsa"
	"github.com/slsa-framework/verifier/pkg/slsa/eval"
	"github.com/slsa-framework/verifier/pkg/slsa/vsa"
	"github.com/slsa-framework/verifier/pkg/subject"
)

// loadFixture parses a fixture through the public collector envelope
// path — the same code the CLI runs.
func loadFixture(t *testing.T, name string) attestation.Statement {
	t.Helper()
	envs, err := envelope.Parsers.ParseFiles([]string{filepath.Join("testdata", "plain", name)})
	require.NoError(t, err, "parsing fixture %s", name)
	require.Len(t, envs, 1)
	stmt := envs[0].GetStatement()
	require.NotNil(t, stmt)
	return stmt
}

// TestFixturesParseToExpectedProtoType walks every plain fixture and
// asserts the predicate type matches the expected URI and the parsed
// payload is the matching upstream proto message — this verifies the
// pkg/slsa/predicate registry routing for all four supported types in
// one place.
func TestFixturesParseToExpectedProtoType(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		predicateID string
		wantPB      func(proto.Message) bool
	}{
		{
			name:        "v01-build.intoto.json",
			predicateID: eval.PredicateProvenanceV01,
			wantPB: func(m proto.Message) bool {
				_, ok := m.(*provenancev01.Provenance)
				return ok
			},
		},
		{
			name:        "v02-build.intoto.json",
			predicateID: eval.PredicateProvenanceV02,
			wantPB: func(m proto.Message) bool {
				_, ok := m.(*provenancev02.Provenance)
				return ok
			},
		},
		{
			name:        "v1-build.intoto.json",
			predicateID: eval.PredicateProvenanceV1,
			wantPB: func(m proto.Message) bool {
				_, ok := m.(*provenancev1.Provenance)
				return ok
			},
		},
		{
			name:        "source.intoto.json",
			predicateID: eval.PredicateSourceProvenance,
			wantPB: func(m proto.Message) bool {
				_, ok := m.(*sourceprovenance.SourceProvenancePred)
				return ok
			},
		},
		{
			name:        "source-legacy.intoto.json",
			predicateID: eval.PredicateSourceProvenance,
			wantPB: func(m proto.Message) bool {
				_, ok := m.(*sourceprovenance.SourceProvenancePred)
				return ok
			},
		},
		{
			name:        "tag.intoto.json",
			predicateID: eval.PredicateTagProvenance,
			wantPB: func(m proto.Message) bool {
				_, ok := m.(*sourceprovenance.TagProvenancePred)
				return ok
			},
		},
		{
			name:        "source-v1.intoto.json",
			predicateID: eval.PredicateSourceProvenanceV1,
			wantPB: func(m proto.Message) bool {
				_, ok := m.(*sourceprovenance.SourceProvenancePred)
				return ok
			},
		},
		{
			name:        "tag-v1.intoto.json",
			predicateID: eval.PredicateTagProvenanceV1,
			wantPB: func(m proto.Message) bool {
				_, ok := m.(*sourceprovenance.TagProvenancePred)
				return ok
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stmt := loadFixture(t, tc.name)
			assert.Equal(t, attestation.PredicateType(tc.predicateID), stmt.GetPredicateType())

			parsed, ok := stmt.GetPredicate().GetParsed().(proto.Message)
			require.True(t, ok, "GetParsed should return a proto.Message")
			assert.True(t, tc.wantPB(parsed), "wrong proto type for %s: got %T", tc.name, parsed)
		})
	}
}

// TestVerifyV1FixtureEndToEnd runs the v1 build fixture through the full
// public Verify flow with all five embedded core controls and confirms a
// PASS at SLSA level 3.
func TestVerifyV1FixtureEndToEnd(t *testing.T) {
	t.Parallel()

	stmt := loadFixture(t, "v1-build.intoto.json")
	v, err := slsa.New()
	require.NoError(t, err)

	res, err := v.Verify(
		context.Background(),
		stmt,
		slsa.WithParam("expected_source", "git+https://example.com/repo"),
		slsa.WithParam("trusted_builders", []string{"https://example.com/builder"}),
	)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 3, res.SLSALevel)
}

// TestVerifyV02FixtureReachesLevel3 confirms the v0.2 build fixture
// passes all five build/core controls (each control carries a
// version-specific check now) and reaches Level 3 with matching
// params.
func TestVerifyV02FixtureReachesLevel3(t *testing.T) {
	t.Parallel()

	stmt := loadFixture(t, "v02-build.intoto.json")
	v, err := slsa.New()
	require.NoError(t, err)

	res, err := v.Verify(
		context.Background(),
		stmt,
		slsa.WithParam("expected_source", "git+https://example.com/repo"),
		slsa.WithParam("trusted_builders", []string{"https://example.com/builder/v0.2"}),
	)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 3, res.SLSALevel)
}

// TestVerifyV01FixtureReachesLevel3 — same as v0.2 but for v0.1.
func TestVerifyV01FixtureReachesLevel3(t *testing.T) {
	t.Parallel()

	stmt := loadFixture(t, "v01-build.intoto.json")
	v, err := slsa.New()
	require.NoError(t, err)

	res, err := v.Verify(
		context.Background(),
		stmt,
		slsa.WithParam("expected_source", "git+https://example.com/repo"),
		slsa.WithParam("trusted_builders", []string{"https://example.com/builder/v0.1"}),
	)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 3, res.SLSALevel)
}

// TestVerifySourceFixtureReachesLevel4 confirms the source fixture
// passes every SourceCore control (L1 expectation checks + the 13
// SLSA_SOURCE_* named controls) and reaches Level 4. Also confirms
// BuildType is empty for source statements (the gating fix).
func TestVerifySourceFixtureReachesLevel4(t *testing.T) {
	t.Parallel()

	stmt := loadFixture(t, "source.intoto.json")
	v, err := slsa.New()
	require.NoError(t, err)

	res, err := v.Verify(
		context.Background(),
		stmt,
		slsa.WithParam("expected_source_repo", "https://github.com/example/repo"),
		slsa.WithParam("expected_branch", "refs/heads/main"),
	)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 4, res.SLSALevel)

	// Source statements get no BuildType controls.
	assert.Empty(t, res.BuildTypeResults, "source statements should produce no BuildType results")

	// 13 named source controls + 3 expectation checks + 5 tag controls
	// (the tag entries report as skipped on branch provenance).
	assert.Len(t, res.CoreResults, 21)
}

// TestVerifySourceFixtureWithoutParams confirms the expectation checks
// (expected_source_repo / expected_branch) are skipped — not errored —
// when the caller states no expectations, and the level still computes.
func TestVerifySourceFixtureWithoutParams(t *testing.T) {
	t.Parallel()

	stmt := loadFixture(t, "source.intoto.json")
	v, err := slsa.New()
	require.NoError(t, err)

	res, err := v.Verify(context.Background(), stmt)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 4, res.SLSALevel)

	for _, cr := range res.CoreResults {
		if cr.ID == "source-repo-match" || cr.ID == "source-branch-match" {
			assert.Equal(t, slsa.StatusSkipped, cr.Status,
				"expectation check %s should be skipped without params", cr.ID)
		}
	}
}

// TestVerifyFinalPredicateTypes confirms the final (non-draft) source
// and tag predicate types are verified exactly like the draft versions.
func TestVerifyFinalPredicateTypes(t *testing.T) {
	t.Parallel()

	v, err := slsa.New()
	require.NoError(t, err)

	res, err := v.Verify(context.Background(), loadFixture(t, "source-v1.intoto.json"))
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 4, res.SLSALevel)

	res, err = v.Verify(
		context.Background(),
		loadFixture(t, "tag-v1.intoto.json"),
		slsa.WithMinLevel(1),
		slsa.WithParam("expected_tag", "v1.2.3"),
	)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 3, res.SLSALevel)
}

// TestVerifyTagFixture confirms tag provenance verification: the tag
// inherits the level attested by the VSA summaries of the tagged
// commit, gated by the tag hygiene control at L2, and the expectation
// checks match the tag predicate's fields.
func TestVerifyTagFixture(t *testing.T) {
	t.Parallel()

	stmt := loadFixture(t, "tag.intoto.json")
	v, err := slsa.New()
	require.NoError(t, err)

	// The fixture's VSA summary attests L3; hygiene is active.
	res, err := v.Verify(
		context.Background(),
		stmt,
		slsa.WithMinLevel(1),
		slsa.WithParam("expected_source_repo", "https://github.com/example/repo"),
		slsa.WithParam("expected_branch", "refs/heads/main"),
		slsa.WithParam("expected_tag", "v1.2.3"),
	)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 3, res.SLSALevel)

	// All branch-provenance controls must have been skipped.
	for _, cr := range res.CoreResults {
		if cr.ID == "source-control-org-scs" || cr.ID == "source-control-scs-continuity" {
			assert.Equal(t, slsa.StatusSkipped, cr.Status, "branch control %s should skip on tag provenance", cr.ID)
		}
	}

	// A wrong expected tag fails the run.
	res, err = v.Verify(
		context.Background(),
		stmt,
		slsa.WithMinLevel(1),
		slsa.WithParam("expected_tag", "v9.9.9"),
	)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusFail, res.Status)

	// A branch not covered by the VSA summaries fails the run.
	res, err = v.Verify(
		context.Background(),
		stmt,
		slsa.WithMinLevel(1),
		slsa.WithParam("expected_branch", "refs/heads/other"),
	)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusFail, res.Status)

	// An enforcement date predating the hygiene control fails the
	// L2 gate: the tag caps at level 1 (sourcetool's no-hygiene
	// degrade), passing only when no higher level is required.
	res, err = v.Verify(
		context.Background(),
		stmt,
		slsa.WithMinLevel(1),
		slsa.WithParam("enforced_since", "2025-01-01T00:00:00Z"),
	)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 1, res.SLSALevel)

	res, err = v.Verify(
		context.Background(),
		stmt,
		slsa.WithMinLevel(3),
		slsa.WithParam("enforced_since", "2025-01-01T00:00:00Z"),
	)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusFail, res.Status)
}

// TestVerifySourceFixtureEnforcedSince confirms the enforced_since param
// fails controls activated after the given date: the fixture's
// two-party review control (since 2025-12-01) drops off, capping the
// level at 3, and the run fails unless MinLevel makes L4 informative.
func TestVerifySourceFixtureEnforcedSince(t *testing.T) {
	t.Parallel()

	stmt := loadFixture(t, "source.intoto.json")
	v, err := slsa.New()
	require.NoError(t, err)

	// Strict (MinLevel unset): the failing L4 control fails the run.
	res, err := v.Verify(
		context.Background(),
		stmt,
		slsa.WithParam("enforced_since", "2025-08-01T00:00:00Z"),
	)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusFail, res.Status)
	assert.Equal(t, 3, res.SLSALevel)

	// With MinLevel 3 the L4 control is informative: PASS at level 3.
	res, err = v.Verify(
		context.Background(),
		stmt,
		slsa.WithParam("enforced_since", "2025-08-01T00:00:00Z"),
		slsa.WithMinLevel(3),
	)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 3, res.SLSALevel)

	// An enforcement date before every control's continuity window
	// cuts deeper: 2025-07-01 predates the L2 continuity control.
	res, err = v.Verify(
		context.Background(),
		stmt,
		slsa.WithParam("enforced_since", "2025-07-01T00:00:00Z"),
		slsa.WithMinLevel(1),
	)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 1, res.SLSALevel)
}

// TestVerifySourceFixtureMissingSinceFails confirms a control listed
// without a since timestamp does not count: the window during which it
// was enforced cannot be established, with or without --since. An
// explicit epoch (the fixture's provenance control) is still a value and
// still counts.
func TestVerifySourceFixtureMissingSinceFails(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("testdata", "plain", "source.intoto.json"))
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	predicate, ok := doc["predicate"].(map[string]any)
	require.True(t, ok)
	controls, ok := predicate["controls"].([]any)
	require.True(t, ok)
	stripped := 0
	for _, c := range controls {
		control, ok := c.(map[string]any)
		require.True(t, ok)
		if control["name"] == "SLSA_SOURCE_ORG_ACCESS_CONTROL" {
			delete(control, "since")
			stripped++
		}
	}
	require.Equal(t, 1, stripped)
	mutated, err := json.Marshal(doc)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "source-no-since.intoto.json")
	require.NoError(t, os.WriteFile(path, mutated, 0o600))

	envs, err := envelope.Parsers.ParseFiles([]string{path})
	require.NoError(t, err)
	require.Len(t, envs, 1)
	stmt := envs[0].GetStatement()
	require.NotNil(t, stmt)

	v, err := slsa.New()
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		opts []slsa.VerificationOption
	}{
		{"without --since", nil},
		{"with --since", []slsa.VerificationOption{slsa.WithParam("enforced_since", "2025-01-01T00:00:00Z")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, err := v.Verify(context.Background(), stmt, tc.opts...)
			require.NoError(t, err)
			assert.Equal(t, slsa.StatusFail, res.Status)

			var accessControl *slsa.ControlResult
			for _, cr := range res.CoreResults {
				if cr.ID == "source-control-org-access-control" {
					accessControl = cr
				}
			}
			require.NotNil(t, accessControl)
			assert.Equal(t, slsa.StatusFail, accessControl.Status, "a control without since must not count")
			// The L2 control failing caps the level at 1.
			assert.Equal(t, 1, res.SLSALevel)
		})
	}
}

// mutatedFixture loads a plain fixture, lets mutate edit its decoded
// JSON, and parses the result back into a statement.
func mutatedFixture(t *testing.T, name string, mutate func(predicate map[string]any)) attestation.Statement {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "plain", name))
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	predicate, ok := doc["predicate"].(map[string]any)
	require.True(t, ok)
	mutate(predicate)
	data, err := json.Marshal(doc)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, data, 0o600))

	envs, err := envelope.Parsers.ParseFiles([]string{path})
	require.NoError(t, err)
	require.Len(t, envs, 1)
	stmt := envs[0].GetStatement()
	require.NotNil(t, stmt)
	return stmt
}

// TestVerifyTagFixtureLevelsFollowTheExpectedBranch confirms a tag's
// inherited level comes from the summary covering the expected branch,
// not from whichever summary happens to carry the highest level.
func TestVerifyTagFixtureLevelsFollowTheExpectedBranch(t *testing.T) {
	t.Parallel()

	stmt := mutatedFixture(t, "tag.intoto.json", func(p map[string]any) {
		p["vsaSummaries"] = []any{
			map[string]any{"sourceRefs": []any{"refs/heads/main"}, "verifiedLevels": []any{"SLSA_SOURCE_LEVEL_1"}},
			map[string]any{"sourceRefs": []any{"refs/heads/release"}, "verifiedLevels": []any{"SLSA_SOURCE_LEVEL_3"}},
		}
	})
	v, err := slsa.New()
	require.NoError(t, err)
	base := []slsa.VerificationOption{
		slsa.WithMinLevel(1),
		slsa.WithParam("expected_source_repo", "https://github.com/example/repo"),
		slsa.WithParam("expected_tag", "v1.2.3"),
	}

	// main was verified at L1 only: expecting main yields L1.
	res, err := v.Verify(context.Background(), stmt, append(base, slsa.WithParam("expected_branch", "refs/heads/main"))...)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 1, res.SLSALevel)

	// Expecting release yields its L3.
	res, err = v.Verify(context.Background(), stmt, append(base, slsa.WithParam("expected_branch", "refs/heads/release"))...)
	require.NoError(t, err)
	assert.Equal(t, 3, res.SLSALevel)

	// Without an expected branch any summary may provide the level.
	res, err = v.Verify(context.Background(), stmt, base...)
	require.NoError(t, err)
	assert.Equal(t, 3, res.SLSALevel)
}

// TestVerifyTagFixtureUnknownLevelDoesNotCount confirms level names are
// matched exactly: an unknown SLSA_SOURCE_LEVEL_* entry attests nothing.
func TestVerifyTagFixtureUnknownLevelDoesNotCount(t *testing.T) {
	t.Parallel()

	stmt := mutatedFixture(t, "tag.intoto.json", func(p map[string]any) {
		p["vsaSummaries"] = []any{
			map[string]any{"sourceRefs": []any{"refs/heads/main"}, "verifiedLevels": []any{"SLSA_SOURCE_LEVEL_FOO", "SLSA_SOURCE_LEVEL_10"}},
		}
	})
	v, err := slsa.New()
	require.NoError(t, err)
	res, err := v.Verify(
		context.Background(),
		stmt,
		slsa.WithMinLevel(1),
		slsa.WithParam("expected_source_repo", "https://github.com/example/repo"),
		slsa.WithParam("expected_branch", "refs/heads/main"),
		slsa.WithParam("expected_tag", "v1.2.3"),
	)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusFail, res.Status)
	assert.Equal(t, 0, res.SLSALevel)
}

// loadBundleFixture parses a Sigstore bundle fixture into its envelope.
func loadBundleFixture(t *testing.T, name string) attestation.Envelope {
	t.Helper()
	envs, err := envelope.Parsers.ParseFiles([]string{filepath.Join("testdata", "bundle", name)})
	require.NoError(t, err, "parsing fixture %s", name)
	require.Len(t, envs, 1)
	return envs[0]
}

// TestBundleFixturesParse walks the Sigstore bundle fixtures: each parses
// to the expected predicate type, carries a signature, and records no
// verification until Verify runs. Signature verification itself needs
// the Sigstore trust root and is not exercised here.
func TestBundleFixturesParse(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name          string
		predicateType string
	}{
		{"source-provenance.sigstore.json", "https://github.com/slsa-framework/slsa-source-poc/source-provenance/v1-draft"},
		{"source-provenance-legacy.sigstore.json", "https://github.com/slsa-framework/slsa-source-poc/source-provenance/v1-draft"},
		{"source-vsa.sigstore.json", "https://slsa.dev/verification_summary/v1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env := loadBundleFixture(t, tc.name)
			stmt := env.GetStatement()
			require.NotNil(t, stmt)
			assert.Equal(t, attestation.PredicateType(tc.predicateType), stmt.GetPredicateType())
			assert.Len(t, env.GetSignatures(), 1, "the bundle is signed")
			assert.Nil(t, env.GetVerification(), "nothing is verified before Verify runs")
		})
	}
}

// TestBundleFixtureSourceProvenanceVerifies runs the source controls over
// the real-world provenance bundle without requiring signatures.
func TestBundleFixtureSourceProvenanceVerifies(t *testing.T) {
	t.Parallel()

	stmt := loadBundleFixture(t, "source-provenance.sigstore.json").GetStatement()
	v, err := slsa.New()
	require.NoError(t, err)
	res, err := v.Verify(
		context.Background(),
		stmt,
		slsa.WithMinLevel(1),
		slsa.WithParam("expected_source_repo", "https://github.com/puerco/lab"),
		slsa.WithParam("expected_branch", "refs/heads/master"),
	)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.GreaterOrEqual(t, res.SLSALevel, 1)
}

// TestBundleFixtureVSAExtracts checks the VSA bundle normalizes to the
// values the workflow issued.
func TestBundleFixtureVSAExtracts(t *testing.T) {
	t.Parallel()

	stmt := loadBundleFixture(t, "source-vsa.sigstore.json").GetStatement()
	got, err := vsa.FromStatement(stmt)
	require.NoError(t, err)
	assert.Equal(t, "https://github.com/slsa-framework/source-actions", got.Verifier.ID)
	assert.True(t, got.Passed())
	assert.Equal(t, []string{"SLSA_SOURCE_LEVEL_1"}, got.VerifiedLevels)
	assert.Equal(t, "git+https://github.com/puerco/lab", got.ResourceURI)
}

// TestVerifyV1FixtureSubjects binds the build fixture to expected
// artifacts: the fixture's subject is out/binary with sha256 deadbeef.
func TestVerifyV1FixtureSubjects(t *testing.T) {
	t.Parallel()

	stmt := loadFixture(t, "v1-build.intoto.json")
	v, err := slsa.New()
	require.NoError(t, err)
	base := []slsa.VerificationOption{
		slsa.WithParam("expected_source", "git+https://example.com/repo"),
		slsa.WithParam("trusted_builders", []string{"https://example.com/builder"}),
	}
	baseline, err := v.Verify(context.Background(), stmt, base...)
	require.NoError(t, err)
	require.Equal(t, slsa.StatusPass, baseline.Status, "the fixture must pass on its own for the subject cases to mean anything")
	assert.Empty(t, baseline.Subjects, "no subjects expected, none reported")

	held := &subject.Expected{Name: "dist/binary", Digests: map[string]string{"sha256": "deadbeef", "sha512": "unrelated"}}
	other := &subject.Expected{Name: "dist/other", Digests: map[string]string{"sha256": "cafebabe"}}

	// The held artifact is the fixture's subject.
	res, err := v.Verify(context.Background(), stmt, append(base, slsa.WithSubjects([]*subject.Expected{held}))...)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusPass, res.Status)
	require.Len(t, res.Subjects, 1)
	assert.True(t, res.Subjects[0].Matched)
	assert.Equal(t, "out/binary", res.Subjects[0].Subject.GetName())
	assert.NotContains(t, res.Message, "subjects not found")

	// One artifact the attestation is not about fails the run, and the
	// per-subject outcomes are all still reported.
	res, err = v.Verify(context.Background(), stmt, append(base, slsa.WithSubjects([]*subject.Expected{held, other}))...)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusFail, res.Status)
	require.Len(t, res.Subjects, 2)
	assert.True(t, res.Subjects[0].Matched)
	assert.False(t, res.Subjects[1].Matched)
	assert.Contains(t, res.Message, "1 of 2 expected subjects not found in the attestation")
	assert.Equal(t, baseline.SLSALevel, res.SLSALevel, "the controls still ran and the level is still computed")
}

// TestVerifyBuildTypeParamsMustBeSet: a provenance whose buildType the
// catalog has parameterized checks for cannot be verified without stating
// at least one of the parameters, unless the checks are skipped.
func TestVerifyBuildTypeParamsMustBeSet(t *testing.T) {
	t.Parallel()

	// The catalog's example buildType control keys on this buildType and
	// takes expected_builder.
	stmt := mutatedFixture(t, "v1-build.intoto.json", func(p map[string]any) {
		bd, ok := p["buildDefinition"].(map[string]any)
		require.True(t, ok)
		bd["buildType"] = "https://example.com/test/buildType@v1"
	})
	v, err := slsa.New()
	require.NoError(t, err)
	base := []slsa.VerificationOption{
		slsa.WithParam("expected_source", "git+https://example.com/repo"),
		slsa.WithParam("trusted_builders", []string{"https://example.com/builder"}),
	}

	_, err = v.Verify(context.Background(), stmt, base...)
	require.ErrorIs(t, err, slsa.ErrBuildTypeParamsUnset)
	assert.Contains(t, err.Error(), "https://example.com/test/buildType@v1")
	assert.Contains(t, err.Error(), "expected_builder")

	res, err := v.Verify(context.Background(), stmt, append(base, slsa.WithParam("expected_builder", "https://example.com/builder"))...)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, slsa.StatusPass, buildTypeResult(t, res, "example-test-builder-id").Status)

	res, err = v.Verify(context.Background(), stmt, append(base, slsa.WithSkipBuildTypeChecks(true))...)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusPass, res.Status)
	example := buildTypeResult(t, res, "example-test-builder-id")
	assert.Equal(t, slsa.StatusSkipped, example.Status)
	assert.Contains(t, example.Message, "expected_builder")
}

// buildTypeResult returns the buildType-layer result with the given id.
func buildTypeResult(t *testing.T, res *slsa.Result, id string) *slsa.ControlResult {
	t.Helper()
	for _, cr := range res.BuildTypeResults {
		if cr.ID == id {
			return cr
		}
	}
	require.Failf(t, "control missing", "no buildType result %q in %+v", id, res.BuildTypeResults)
	return nil
}

// TestGitHubBuildTypeControls runs the GitHub-specific buildType controls
// over real generator provenance for each family: branch and tag
// expectations, the tag-build branch fallback, semantic versions, and
// workflow_dispatch inputs.
func TestGitHubBuildTypeControls(t *testing.T) {
	t.Parallel()

	v, err := slsa.New()
	require.NoError(t, err)

	for _, tc := range []struct {
		name    string
		fixture string
		params  map[string]any
		want    map[string]slsa.Status // control id → status; absent ids are not asserted
	}{
		// --- v0.2 Go builder, branch build triggered by schedule ---
		{
			name:    "branch build, expected branch bare",
			fixture: "gha-go-v02-branch.intoto.json",
			params:  map[string]any{"expected_branch": "main"},
			want:    map[string]slsa.Status{"github-source-branch": slsa.StatusPass},
		},
		{
			name:    "branch build, expected branch as ref",
			fixture: "gha-go-v02-branch.intoto.json",
			params:  map[string]any{"expected_branch": "refs/heads/main"},
			want:    map[string]slsa.Status{"github-source-branch": slsa.StatusPass},
		},
		{
			name:    "branch build, other branch",
			fixture: "gha-go-v02-branch.intoto.json",
			params:  map[string]any{"expected_branch": "release"},
			want:    map[string]slsa.Status{"github-source-branch": slsa.StatusFail},
		},
		{
			name:    "branch build cannot meet a tag expectation",
			fixture: "gha-go-v02-branch.intoto.json",
			params:  map[string]any{"expected_tag": "v1.0.0", "expected_versioned_tag": "v1"},
			want:    map[string]slsa.Status{"github-source-tag": slsa.StatusFail, "github-source-versioned-tag": slsa.StatusFail},
		},
		{
			name:    "unset expectations are skipped once one is set",
			fixture: "gha-go-v02-branch.intoto.json",
			params:  map[string]any{"expected_branch": "main"},
			want:    map[string]slsa.Status{"github-source-tag": slsa.StatusSkipped, "github-source-versioned-tag": slsa.StatusSkipped, "github-workflow-inputs": slsa.StatusSkipped},
		},
		// --- v0.2 generic generator, tag push, no base_ref anywhere ---
		{
			name:    "tag build, exact tag",
			fixture: "gha-generic-v02-tag.intoto.json",
			params:  map[string]any{"expected_tag": "v1.5.0"},
			want:    map[string]slsa.Status{"github-source-tag": slsa.StatusPass},
		},
		{
			name:    "tag build, exact tag as ref",
			fixture: "gha-generic-v02-tag.intoto.json",
			params:  map[string]any{"expected_tag": "refs/tags/v1.5.0"},
			want:    map[string]slsa.Status{"github-source-tag": slsa.StatusPass},
		},
		{
			name:    "tag build, other tag",
			fixture: "gha-generic-v02-tag.intoto.json",
			params:  map[string]any{"expected_tag": "v1.5.1"},
			want:    map[string]slsa.Status{"github-source-tag": slsa.StatusFail},
		},
		{
			name:    "tag build, versioned tag major",
			fixture: "gha-generic-v02-tag.intoto.json",
			params:  map[string]any{"expected_versioned_tag": "v1"},
			want:    map[string]slsa.Status{"github-source-versioned-tag": slsa.StatusPass},
		},
		{
			name:    "tag build, versioned tag minor",
			fixture: "gha-generic-v02-tag.intoto.json",
			params:  map[string]any{"expected_versioned_tag": "v1.5"},
			want:    map[string]slsa.Status{"github-source-versioned-tag": slsa.StatusPass},
		},
		{
			name:    "tag build, versioned tag other minor",
			fixture: "gha-generic-v02-tag.intoto.json",
			params:  map[string]any{"expected_versioned_tag": "v1.6"},
			want:    map[string]slsa.Status{"github-source-versioned-tag": slsa.StatusFail},
		},
		{
			name:    "tag build without a recorded branch cannot meet a branch expectation",
			fixture: "gha-generic-v02-tag.intoto.json",
			params:  map[string]any{"expected_branch": "main"},
			want:    map[string]slsa.Status{"github-source-branch": slsa.StatusFail},
		},
		// --- v1 BYOB delegator, tag push whose event payload names the branch ---
		{
			name:    "v1 tag build, exact tag",
			fixture: "gha-delegator-v1-tag.intoto.json",
			params:  map[string]any{"expected_tag": "v13.0.30"},
			want:    map[string]slsa.Status{"github-source-tag": slsa.StatusPass},
		},
		{
			name:    "v1 tag build, versioned tag",
			fixture: "gha-delegator-v1-tag.intoto.json",
			params:  map[string]any{"expected_versioned_tag": "v13"},
			want:    map[string]slsa.Status{"github-source-versioned-tag": slsa.StatusPass},
		},
		{
			name:    "v1 tag build, branch from the push event's base_ref",
			fixture: "gha-delegator-v1-tag.intoto.json",
			params:  map[string]any{"expected_branch": "main"},
			want:    map[string]slsa.Status{"github-source-branch": slsa.StatusPass},
		},
		{
			name:    "v1 tag build, other branch",
			fixture: "gha-delegator-v1-tag.intoto.json",
			params:  map[string]any{"expected_branch": "develop"},
			want:    map[string]slsa.Status{"github-source-branch": slsa.StatusFail},
		},
		// --- v0.2 generic generator, workflow_dispatch with inputs ---
		{
			name:    "workflow inputs all present",
			fixture: "gha-generic-v02-workflow-dispatch.intoto.json",
			params:  map[string]any{"expected_workflow_inputs": []string{"some_bool=true", "some_integer=123"}},
			want:    map[string]slsa.Status{"github-workflow-inputs": slsa.StatusPass},
		},
		{
			name:    "workflow input with another value",
			fixture: "gha-generic-v02-workflow-dispatch.intoto.json",
			params:  map[string]any{"expected_workflow_inputs": []string{"some_bool=false"}},
			want:    map[string]slsa.Status{"github-workflow-inputs": slsa.StatusFail},
		},
		{
			name:    "workflow input missing",
			fixture: "gha-generic-v02-workflow-dispatch.intoto.json",
			params:  map[string]any{"expected_workflow_inputs": []string{"nope=1"}},
			want:    map[string]slsa.Status{"github-workflow-inputs": slsa.StatusFail},
		},
		{
			name:    "workflow inputs on a build not triggered by workflow_dispatch",
			fixture: "gha-go-v02-branch.intoto.json",
			params:  map[string]any{"expected_workflow_inputs": []string{"some_bool=true"}},
			want:    map[string]slsa.Status{"github-workflow-inputs": slsa.StatusFail},
		},
		// --- v1 GitHub artifact attestation, branch build ---
		{
			name:    "github attestation, branch",
			fixture: "github-attestation-v1-branch.intoto.json",
			params:  map[string]any{"expected_branch": "publish-to-bcr"},
			want:    map[string]slsa.Status{"github-source-branch": slsa.StatusPass},
		},
		{
			name:    "github attestation, tag expectation on a branch build",
			fixture: "github-attestation-v1-branch.intoto.json",
			params:  map[string]any{"expected_tag": "v1"},
			want:    map[string]slsa.Status{"github-source-tag": slsa.StatusFail},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stmt := loadFixture(t, tc.fixture)
			opts := make([]slsa.VerificationOption, 0, 2+len(tc.params))
			// The core layer needs these; the buildType layer is what we assert.
			opts = append(opts,
				slsa.WithParam("expected_source", "unused"),
				slsa.WithParam("trusted_builders", []string{"unused"}),
			)
			for k, val := range tc.params {
				opts = append(opts, slsa.WithParam(k, val))
			}
			res, err := v.Verify(context.Background(), stmt, opts...)
			require.NoError(t, err)
			for id, want := range tc.want {
				cr := buildTypeResult(t, res, id)
				assert.Equal(t, want, cr.Status, "%s: %s", id, cr.Message)
			}
		})
	}
}

// A generator provenance verified with no expectation stated is refused,
// naming every expectation the catalog can check for it.
func TestGitHubBuildTypeControlsRequireAnExpectation(t *testing.T) {
	t.Parallel()
	v, err := slsa.New()
	require.NoError(t, err)
	_, err = v.Verify(context.Background(), loadFixture(t, "gha-go-v02-branch.intoto.json"),
		slsa.WithParam("expected_source", "unused"), slsa.WithParam("trusted_builders", []string{"unused"}))
	require.ErrorIs(t, err, slsa.ErrBuildTypeParamsUnset)
	for _, p := range []string{"expected_branch", "expected_tag", "expected_versioned_tag", "expected_workflow_inputs"} {
		assert.Contains(t, err.Error(), p)
	}
}

// coreResult returns the core-layer result for control id.
func coreResult(t *testing.T, res *slsa.Result, id string) *slsa.ControlResult {
	t.Helper()
	for _, cr := range res.CoreResults {
		if cr.ID == id {
			return cr
		}
	}
	require.Failf(t, "control missing", "no core result %q in %+v", id, res.CoreResults)
	return nil
}

// TestSourceRepoMatchAcrossGenerators checks source-repo-match finds the
// repository wherever each generator recorded it: the BYOB delegator
// (resolvedDependencies), GitHub artifact attestations
// (workflow.repository and resolvedDependencies), the v0.2 generators
// (configSource) and the synthetic fixtures (externalParameters.source,
// configSource over materials, and v0.1 materials) — with the
// expectation spelled with or without a scheme, and refused when it
// carries a ref.
func TestSourceRepoMatchAcrossGenerators(t *testing.T) {
	t.Parallel()

	v, err := slsa.New()
	require.NoError(t, err)

	for _, tc := range []struct {
		name     string
		fixture  string
		expected string
		want     slsa.Status
	}{
		{name: "delegator BYOB, scheme-less", fixture: "gha-delegator-v1-tag.intoto.json", expected: "github.com/slsa-framework/example-package", want: slsa.StatusPass},
		{name: "delegator BYOB, https", fixture: "gha-delegator-v1-tag.intoto.json", expected: "https://github.com/slsa-framework/example-package", want: slsa.StatusPass},
		{name: "delegator BYOB, git+https", fixture: "gha-delegator-v1-tag.intoto.json", expected: "git+https://github.com/slsa-framework/example-package", want: slsa.StatusPass},
		{name: "delegator BYOB, other repository", fixture: "gha-delegator-v1-tag.intoto.json", expected: "github.com/slsa-framework/other", want: slsa.StatusFail},
		{name: "GitHub attestation", fixture: "github-attestation-v1-branch.intoto.json", expected: "https://github.com/aspect-build/rules_lint", want: slsa.StatusPass},
		{name: "GitHub attestation, other repository", fixture: "github-attestation-v1-branch.intoto.json", expected: "https://github.com/aspect-build/rules_go", want: slsa.StatusFail},
		{name: "v0.2 generic generator", fixture: "gha-generic-v02-tag.intoto.json", expected: "github.com/asraa/slsa-on-github-test", want: slsa.StatusPass},
		{name: "v0.2 go builder", fixture: "gha-go-v02-branch.intoto.json", expected: "github.com/slsa-framework/example-package", want: slsa.StatusPass},
		{name: "v0.2 go builder, other repository", fixture: "gha-go-v02-branch.intoto.json", expected: "github.com/slsa-framework/example-package-fork", want: slsa.StatusFail},
		{name: "v1 externalParameters.source", fixture: "v1-build.intoto.json", expected: "example.com/repo", want: slsa.StatusPass},
		{name: "tejolote release provenance", fixture: "tejolote-v1-tag.intoto.json", expected: "github.com/carabiner-dev/bnd", want: slsa.StatusPass},
		{name: "v0.2 configSource wins over materials", fixture: "v02-build.intoto.json", expected: "example.com/dep", want: slsa.StatusFail},
		{name: "v0.1 materials", fixture: "v01-build.intoto.json", expected: "example.com/repo", want: slsa.StatusPass},
		{name: "expectation with a ref is an error", fixture: "gha-delegator-v1-tag.intoto.json", expected: "github.com/slsa-framework/example-package@refs/tags/v13.0.30", want: slsa.StatusError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, err := v.Verify(context.Background(), loadFixture(t, tc.fixture),
				slsa.WithParam("expected_source", tc.expected),
				slsa.WithParam("trusted_builders", []string{"unused"}),
				slsa.WithSkipBuildTypeChecks(true),
			)
			require.NoError(t, err)
			cr := coreResult(t, res, "source-repo-match")
			assert.Equal(t, tc.want, cr.Status, "%s: %s", cr.ID, cr.Message)
			if tc.want == slsa.StatusError {
				assert.Contains(t, cr.Message, "must not carry a ref")
			}
		})
	}
}

// controlStatus returns the status of the core control with id.
func controlStatus(t *testing.T, res *slsa.Result, id string) slsa.Status {
	t.Helper()
	for _, cr := range res.CoreResults {
		if cr.ID == id {
			return cr.Status
		}
	}
	t.Fatalf("control %q not in the results", id)
	return ""
}

// TestVerifyLegacySourceFixture covers provenance issued by sourcetool
// before v0.7.0, which listed only branch continuity, tag hygiene and
// provenance under their old names. The platform controls are inferred
// for a GitHub repository and the old names map to the controls
// sourcetool derived from them, so it evaluates to the level sourcetool
// computed at the time.
func TestVerifyLegacySourceFixture(t *testing.T) {
	t.Parallel()

	stmt := loadFixture(t, "source-legacy.intoto.json")
	v, err := slsa.New()
	require.NoError(t, err)

	res, err := v.Verify(
		context.Background(),
		stmt,
		slsa.WithMinLevel(1),
		slsa.WithParam("expected_source_repo", "https://github.com/example/repo"),
		slsa.WithParam("expected_branch", "refs/heads/main"),
	)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 3, res.SLSALevel)
	for _, id := range []string{
		"source-control-org-scs", "source-control-scs-repo-id", "source-control-scs-identity",
		"source-control-org-access-control", "source-control-org-safe-expunge",
		"source-control-scs-continuity", "source-control-org-continuity",
		"source-control-scs-protected-refs", "source-control-scs-provenance",
	} {
		assert.Equal(t, slsa.StatusPass, controlStatus(t, res, id), id)
	}
	assert.Equal(t, slsa.StatusFail, controlStatus(t, res, "source-control-scs-two-party-review"))

	// An enforcement date before tag hygiene drops the controls derived
	// from it: safe expunge at L2 and protected refs at L3.
	res, err = v.Verify(
		context.Background(),
		stmt,
		slsa.WithMinLevel(1),
		slsa.WithParam("enforced_since", "2025-07-01T00:00:00Z"),
	)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 1, res.SLSALevel)
	assert.Equal(t, slsa.StatusFail, controlStatus(t, res, "source-control-org-safe-expunge"))
	assert.Equal(t, slsa.StatusFail, controlStatus(t, res, "source-control-scs-protected-refs"))
	assert.Equal(t, slsa.StatusPass, controlStatus(t, res, "source-control-scs-continuity"))
	// The inherent platform controls are not dated, they always hold
	assert.Equal(t, slsa.StatusPass, controlStatus(t, res, "source-control-org-scs"))
}

// TestVerifyLegacySourceFixtureNotOnGitHub confirms the platform controls
// are only inferred for repositories hosted on GitHub.
func TestVerifyLegacySourceFixtureNotOnGitHub(t *testing.T) {
	t.Parallel()

	stmt := mutatedFixture(t, "source-legacy.intoto.json", func(predicate map[string]any) {
		predicate["repoUri"] = "https://gitlab.com/example/repo"
	})
	v, err := slsa.New()
	require.NoError(t, err)

	res, err := v.Verify(context.Background(), stmt, slsa.WithMinLevel(1))
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusFail, res.Status)
	assert.Equal(t, 0, res.SLSALevel)
	assert.Equal(t, slsa.StatusFail, controlStatus(t, res, "source-control-org-scs"))
	// The mapped names still count
	assert.Equal(t, slsa.StatusPass, controlStatus(t, res, "source-control-org-continuity"))
}

// TestVerifySourceFixtureMissingPlatformControlFails confirms nothing is
// inferred for provenance that names the current controls: omitting a
// platform control there is a statement, not a legacy artifact.
func TestVerifySourceFixtureMissingPlatformControlFails(t *testing.T) {
	t.Parallel()

	stmt := mutatedFixture(t, "source.intoto.json", func(predicate map[string]any) {
		controls, ok := predicate["controls"].([]any)
		require.True(t, ok)
		kept := []any{}
		for _, c := range controls {
			control, ok := c.(map[string]any)
			require.True(t, ok)
			if control["name"] != "SLSA_SOURCE_SCS_REPO_ID" {
				kept = append(kept, c)
			}
		}
		require.Len(t, kept, len(controls)-1)
		predicate["controls"] = kept
	})
	v, err := slsa.New()
	require.NoError(t, err)

	res, err := v.Verify(context.Background(), stmt, slsa.WithMinLevel(1))
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusFail, res.Status)
	assert.Equal(t, 0, res.SLSALevel)
	assert.Equal(t, slsa.StatusFail, controlStatus(t, res, "source-control-scs-repo-id"))
	assert.Equal(t, slsa.StatusPass, controlStatus(t, res, "source-control-org-scs"))
}

// TestBundleFixtureLegacySourceProvenanceVerifies runs the source controls
// over real-world legacy provenance: the go-vex commit attested by the
// official workflow running sourcetool v0.6.2, which its VSA rates at L3.
func TestBundleFixtureLegacySourceProvenanceVerifies(t *testing.T) {
	t.Parallel()

	stmt := loadBundleFixture(t, "source-provenance-legacy.sigstore.json").GetStatement()
	v, err := slsa.New()
	require.NoError(t, err)
	res, err := v.Verify(
		context.Background(),
		stmt,
		slsa.WithMinLevel(1),
		slsa.WithParam("expected_source_repo", "https://github.com/openvex/go-vex"),
		slsa.WithParam("expected_branch", "refs/heads/main"),
	)
	require.NoError(t, err)
	assert.Equal(t, slsa.StatusPass, res.Status)
	assert.Equal(t, 3, res.SLSALevel)
}
