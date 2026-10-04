// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func pass(id string, level int) *ControlResult {
	return &ControlResult{ID: id, SLSALevel: level, Status: StatusPass}
}

func skip(id string, level int) *ControlResult {
	return &ControlResult{ID: id, SLSALevel: level, Status: StatusSkipped}
}

func fail(id string, level int) *ControlResult {
	return &ControlResult{ID: id, SLSALevel: level, Status: StatusFail}
}

func TestComputeResultAllPass(t *testing.T) {
	t.Parallel()

	impl := &defaultImplementation{}
	r, err := impl.ComputeResult(
		nil,
		[]*ControlResult{pass("a", 1), pass("b", 2)},
		[]*ControlResult{pass("c", 0)},
		[]*ControlResult{pass("d", 0)},
	)
	require.NoError(t, err)
	assert.Equal(t, StatusPass, r.Status)
	assert.Equal(t, 2, r.SLSALevel)
}

func TestComputeResultCoreFailDropsToPriorLevel(t *testing.T) {
	t.Parallel()

	impl := &defaultImplementation{}
	r, err := impl.ComputeResult(
		nil,
		[]*ControlResult{pass("a", 1), fail("b", 2)},
		nil,
		nil,
	)
	require.NoError(t, err)
	assert.Equal(t, StatusFail, r.Status)
	assert.Equal(t, 1, r.SLSALevel)
}

func TestComputeResultLevel1FailReportsLevel0(t *testing.T) {
	t.Parallel()

	impl := &defaultImplementation{}
	r, err := impl.ComputeResult(
		nil,
		[]*ControlResult{fail("a", 1)},
		nil,
		nil,
	)
	require.NoError(t, err)
	assert.Equal(t, StatusFail, r.Status)
	assert.Equal(t, 0, r.SLSALevel)
}

func TestComputeResultEmptyLevelsAreSkipped(t *testing.T) {
	t.Parallel()

	impl := &defaultImplementation{}
	// Levels 1 and 3 are filled; level 2 is empty. Achievable max is 3.
	r, err := impl.ComputeResult(
		nil,
		[]*ControlResult{pass("a", 1), pass("c", 3)},
		nil,
		nil,
	)
	require.NoError(t, err)
	assert.Equal(t, 3, r.SLSALevel)
}

func TestComputeResultUserFailMakesOverallFail(t *testing.T) {
	t.Parallel()

	impl := &defaultImplementation{}
	r, err := impl.ComputeResult(
		nil,
		[]*ControlResult{pass("a", 1)},
		nil,
		[]*ControlResult{fail("u", 0)},
	)
	require.NoError(t, err)
	assert.Equal(t, StatusFail, r.Status)
	// Core controls all passed at level 1.
	assert.Equal(t, 1, r.SLSALevel)
}

func TestComputeResultBuildTypeFailMakesOverallFail(t *testing.T) {
	t.Parallel()

	impl := &defaultImplementation{}
	r, err := impl.ComputeResult(
		nil,
		[]*ControlResult{pass("a", 1)},
		[]*ControlResult{fail("bt", 0)},
		nil,
	)
	require.NoError(t, err)
	assert.Equal(t, StatusFail, r.Status)
}

func TestComputeResultErrorTreatedAsFail(t *testing.T) {
	t.Parallel()

	impl := &defaultImplementation{}
	r, err := impl.ComputeResult(
		nil,
		[]*ControlResult{{ID: "a", SLSALevel: 1, Status: StatusError}},
		nil,
		nil,
	)
	require.NoError(t, err)
	assert.Equal(t, StatusFail, r.Status)
	assert.Equal(t, 0, r.SLSALevel)
}

func TestComputeResultMinLevel(t *testing.T) {
	t.Parallel()

	impl := &defaultImplementation{}

	// A failing core control above MinLevel is informative: the run
	// passes and the failing level caps the computed SLSA level.
	r, err := impl.ComputeResult(
		&VerificationOptions{MinLevel: 3},
		[]*ControlResult{pass("a", 1), pass("b", 2), pass("c", 3), fail("d", 4)},
		nil,
		nil,
	)
	require.NoError(t, err)
	assert.Equal(t, StatusPass, r.Status)
	assert.Equal(t, 3, r.SLSALevel)

	// A failing core control at or below MinLevel still fails the run.
	r, err = impl.ComputeResult(
		&VerificationOptions{MinLevel: 3},
		[]*ControlResult{pass("a", 1), pass("b", 2), fail("c", 3), fail("d", 4)},
		nil,
		nil,
	)
	require.NoError(t, err)
	assert.Equal(t, StatusFail, r.Status)
	assert.Equal(t, 2, r.SLSALevel)

	// Core controls without a declared level are always required.
	r, err = impl.ComputeResult(
		&VerificationOptions{MinLevel: 3},
		[]*ControlResult{pass("a", 1), fail("unleveled", 0)},
		nil,
		nil,
	)
	require.NoError(t, err)
	assert.Equal(t, StatusFail, r.Status)

	// BuildType and user controls are always required too.
	r, err = impl.ComputeResult(
		&VerificationOptions{MinLevel: 3},
		[]*ControlResult{pass("a", 1)},
		nil,
		[]*ControlResult{fail("user", 4)},
	)
	require.NoError(t, err)
	assert.Equal(t, StatusFail, r.Status)

	// MinLevel zero keeps the strict semantics.
	r, err = impl.ComputeResult(
		&VerificationOptions{MinLevel: 0},
		[]*ControlResult{pass("a", 1), fail("d", 4)},
		nil,
		nil,
	)
	require.NoError(t, err)
	assert.Equal(t, StatusFail, r.Status)
}

// Requiring a level means reaching it: a computed level below MinLevel
// fails the run even when no control failed, which is what happens when
// the controls at the required level are skipped or not declared.
func TestComputeResultMinLevelMustBeReached(t *testing.T) {
	t.Parallel()

	impl := &defaultImplementation{}

	// Level 4 controls skipped: the level tops out at 3.
	r, err := impl.ComputeResult(
		&VerificationOptions{MinLevel: 4},
		[]*ControlResult{pass("a", 1), pass("b", 2), pass("c", 3), skip("d", 4)},
		nil,
		nil,
	)
	require.NoError(t, err)
	assert.Equal(t, StatusFail, r.Status)
	assert.Equal(t, 3, r.SLSALevel)
	assert.Equal(t, "SLSA level 3 is below the required level 4", r.Message)

	// No level 4 control declared at all.
	r, err = impl.ComputeResult(
		&VerificationOptions{MinLevel: 4},
		[]*ControlResult{pass("a", 1), pass("b", 2), pass("c", 3)},
		nil,
		nil,
	)
	require.NoError(t, err)
	assert.Equal(t, StatusFail, r.Status)
	assert.Equal(t, 3, r.SLSALevel)

	// Everything skipped: level 0, which is below any requirement.
	r, err = impl.ComputeResult(
		&VerificationOptions{MinLevel: 2},
		[]*ControlResult{skip("a", 1), skip("b", 2)},
		nil,
		nil,
	)
	require.NoError(t, err)
	assert.Equal(t, StatusFail, r.Status)
	assert.Equal(t, 0, r.SLSALevel)
	assert.Contains(t, r.Message, "level 0 is below the required level 2")

	// Reaching the minimum exactly passes, with no message.
	r, err = impl.ComputeResult(
		&VerificationOptions{MinLevel: 3},
		[]*ControlResult{pass("a", 1), pass("b", 2), pass("c", 3), skip("d", 4)},
		nil,
		nil,
	)
	require.NoError(t, err)
	assert.Equal(t, StatusPass, r.Status)
	assert.Equal(t, 3, r.SLSALevel)
	assert.Empty(t, r.Message)
}

func TestComputeResultAllEmpty(t *testing.T) {
	t.Parallel()

	impl := &defaultImplementation{}
	r, err := impl.ComputeResult(nil, nil, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, StatusPass, r.Status)
	assert.Equal(t, 0, r.SLSALevel)
}
