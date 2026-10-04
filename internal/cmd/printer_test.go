// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fatih/color"
	"github.com/stretchr/testify/assert"

	"github.com/slsa-framework/verifier/pkg/slsa"
)

// withNoColor pins color.NoColor=true so tests get the deterministic
// bracketed output regardless of the test runner's TTY state.
func withNoColor(t *testing.T) {
	t.Helper()
	prev := color.NoColor
	color.NoColor = true
	t.Cleanup(func() { color.NoColor = prev })
}

func TestPrintResultPassRoster(t *testing.T) {
	withNoColor(t)

	res := &slsa.Result{
		Status:    slsa.StatusPass,
		SLSALevel: 2,
		CoreResults: []*slsa.ControlResult{
			{ID: "source-repo-match", SLSALevel: 1, Status: slsa.StatusPass, Title: "Source"},
			{ID: "builder-id-trusted", SLSALevel: 2, Status: slsa.StatusPass, Title: "Builder"},
		},
	}
	var buf bytes.Buffer
	printResult(&buf, res, false)

	out := buf.String()
	assert.True(t, strings.HasPrefix(out, "PASS"), "first line should be PASS")
	assert.Contains(t, out, "SLSA Level: 2")
	assert.Contains(t, out, "[PASS]")
	assert.Contains(t, out, "L1")
	assert.Contains(t, out, "L2")
	assert.Contains(t, out, "source-repo-match")
	assert.Contains(t, out, "builder-id-trusted")
	// Title is omitted in non-verbose mode.
	assert.NotContains(t, out, "Source\n")
}

func TestPrintResultHidesSkippedByDefault(t *testing.T) {
	withNoColor(t)

	res := &slsa.Result{
		Status:    slsa.StatusPass,
		SLSALevel: 1,
		CoreResults: []*slsa.ControlResult{
			{ID: "applied", SLSALevel: 1, Status: slsa.StatusPass, Title: "Applied"},
			{ID: "not-applicable", SLSALevel: 2, Status: slsa.StatusSkipped, Title: "Skipped"},
		},
	}

	var buf bytes.Buffer
	printResult(&buf, res, false)
	out := buf.String()
	assert.Contains(t, out, "applied")
	assert.NotContains(t, out, "not-applicable", "skipped controls hidden in non-verbose mode")
	assert.NotContains(t, out, "[SKIP]")
}

func TestPrintResultVerboseShowsSkipped(t *testing.T) {
	withNoColor(t)

	res := &slsa.Result{
		Status: slsa.StatusPass,
		CoreResults: []*slsa.ControlResult{
			{ID: "applied", SLSALevel: 1, Status: slsa.StatusPass, Title: "Applied control"},
			{ID: "not-applicable", SLSALevel: 2, Status: slsa.StatusSkipped, Title: "Skipped control"},
		},
	}

	var buf bytes.Buffer
	printResult(&buf, res, true)
	out := buf.String()
	assert.Contains(t, out, "applied")
	assert.Contains(t, out, "not-applicable")
	assert.Contains(t, out, "[SKIP]")
	// Verbose mode includes titles.
	assert.Contains(t, out, "Applied control")
	assert.Contains(t, out, "Skipped control")
}

func TestPrintResultFailShowsMessageInline(t *testing.T) {
	withNoColor(t)

	res := &slsa.Result{
		Status: slsa.StatusFail,
		CoreResults: []*slsa.ControlResult{
			{ID: "builder-id-trusted", SLSALevel: 2, Status: slsa.StatusFail, Title: "Trusted builder", Message: "builder.id not in allowlist"},
		},
	}
	var buf bytes.Buffer
	printResult(&buf, res, false)
	out := buf.String()
	assert.True(t, strings.HasPrefix(out, "FAIL"))
	assert.Contains(t, out, "[FAIL]")
	assert.Contains(t, out, "builder-id-trusted")
	assert.Contains(t, out, "builder.id not in allowlist")
}

func TestPrintResultEmptyLayerPrintsPlaceholder(t *testing.T) {
	withNoColor(t)

	// An evaluated-but-empty buildType layer prints the placeholder.
	res := &slsa.Result{Status: slsa.StatusPass, BuildTypeResults: []*slsa.ControlResult{}}
	var buf bytes.Buffer
	printResult(&buf, res, false)
	out := buf.String()
	assert.Contains(t, out, "Core controls:\n  (none)")
	assert.Contains(t, out, "BuildType controls:\n  (none)")
	assert.Contains(t, out, "User controls:\n  (none)")
}

func TestPrintResultOmitsUnevaluatedBuildTypeLayer(t *testing.T) {
	withNoColor(t)

	// A nil buildType slice means the layer never ran (source track):
	// the section is omitted entirely.
	res := &slsa.Result{Status: slsa.StatusPass}
	var buf bytes.Buffer
	printResult(&buf, res, false)
	out := buf.String()
	assert.NotContains(t, out, "BuildType")
	assert.Contains(t, out, "Core controls:\n  (none)")
	assert.Contains(t, out, "User controls:\n  (none)")
}

func TestPrintResultAllSkippedInLayerShowsApplicableNote(t *testing.T) {
	withNoColor(t)

	res := &slsa.Result{
		Status: slsa.StatusPass,
		CoreResults: []*slsa.ControlResult{
			{ID: "v1-only-control", SLSALevel: 2, Status: slsa.StatusSkipped, Title: "Only fires for v1"},
		},
	}

	var buf bytes.Buffer
	printResult(&buf, res, false)
	out := buf.String()
	assert.Contains(t, out, "Core controls:\n  (no applicable controls)")
}

func TestPrintResultShowsResultMessage(t *testing.T) {
	withNoColor(t)

	res := &slsa.Result{
		Status:    slsa.StatusFail,
		SLSALevel: 2,
		Message:   "SLSA level 2 is below the required level 3",
		CoreResults: []*slsa.ControlResult{
			{ID: "a", SLSALevel: 1, Status: slsa.StatusPass},
			{ID: "b", SLSALevel: 2, Status: slsa.StatusPass},
		},
	}
	var buf bytes.Buffer
	printResult(&buf, res, false)
	out := buf.String()
	assert.True(t, strings.HasPrefix(out, "FAIL\nSLSA Level: 2\nSLSA level 2 is below the required level 3\n"), out)
}
