// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJoinMessages(t *testing.T) {
	t.Parallel()
	assert.Empty(t, joinMessages("", ""))
	assert.Equal(t, "a", joinMessages("a", ""))
	assert.Equal(t, "b", joinMessages("", "b"))
	assert.Equal(t, "a; b", joinMessages("a", "b"))
}
