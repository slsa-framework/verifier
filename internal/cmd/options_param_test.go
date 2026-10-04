// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseParamString(t *testing.T) {
	t.Parallel()

	name, val, err := parseParam("foo:bar")
	require.NoError(t, err)
	assert.Equal(t, "foo", name)
	assert.Equal(t, "bar", val)
}

func TestParseParamStringWithComma(t *testing.T) {
	t.Parallel()

	// A bare string value with a comma is preserved as-is — not a list,
	// because the value isn't bracketed.
	name, val, err := parseParam("name:Juan Perez, Esquire")
	require.NoError(t, err)
	assert.Equal(t, "name", name)
	assert.Equal(t, "Juan Perez, Esquire", val)
}

func TestParseParamList(t *testing.T) {
	t.Parallel()

	name, val, err := parseParam("names:[Juan Perez, John Peters]")
	require.NoError(t, err)
	assert.Equal(t, "names", name)
	assert.Equal(t, []string{"Juan Perez", "John Peters"}, val)
}

func TestParseParamListWithQuotedCommas(t *testing.T) {
	t.Parallel()

	name, val, err := parseParam(`names:["Juan Perez, Esquire", John Peters]`)
	require.NoError(t, err)
	assert.Equal(t, "names", name)
	assert.Equal(t, []string{"Juan Perez, Esquire", "John Peters"}, val)
}

func TestParseParamColonInValue(t *testing.T) {
	t.Parallel()

	// URL-style values with colons must split on the first one only.
	name, val, err := parseParam("source:git+https://example.com/repo")
	require.NoError(t, err)
	assert.Equal(t, "source", name)
	assert.Equal(t, "git+https://example.com/repo", val)
}

func TestParseParamEmptyValue(t *testing.T) {
	t.Parallel()

	name, val, err := parseParam("foo:")
	require.NoError(t, err)
	assert.Equal(t, "foo", name)
	assert.Empty(t, val)
}

func TestParseParamErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input string
	}{
		{"missing colon", "foo"},
		{"empty name", ":bar"},
		{"only whitespace name", "   :bar"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := parseParam(tc.input)
			assert.Error(t, err)
		})
	}
}

func TestParseParamsMultiple(t *testing.T) {
	t.Parallel()

	parsed, err := parseParams([]string{
		"foo:bar",
		"names:[a, b, c]",
		"source:git+https://example.com/repo",
	})
	require.NoError(t, err)
	assert.Equal(t, "bar", parsed["foo"])
	assert.Equal(t, []string{"a", "b", "c"}, parsed["names"])
	assert.Equal(t, "git+https://example.com/repo", parsed["source"])
}

func TestParseParamsErrorPropagates(t *testing.T) {
	t.Parallel()

	_, err := parseParams([]string{"foo:bar", "broken-no-colon"})
	require.Error(t, err)
}

func TestParamOptionsValidate(t *testing.T) {
	t.Parallel()

	po := &paramOptions{Raw: []string{"foo:bar", "names:[x, y]"}}
	require.NoError(t, po.Validate())
	assert.Equal(t, "bar", po.Params["foo"])
	assert.Equal(t, []string{"x", "y"}, po.Params["names"])
}
