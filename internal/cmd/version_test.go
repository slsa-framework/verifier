// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strings"
	"testing"
)

func TestResolvedVersion(t *testing.T) {
	t.Cleanup(func() { version = "devel" })

	// A release build stamps the version, which wins over anything else.
	version = "v1.2.3"
	if got := resolvedVersion(); got != "v1.2.3" {
		t.Errorf("stamped: resolvedVersion() = %q", got)
	}

	// Without a stamp the module information decides; in a test binary it
	// carries no release, so the result is "devel" or whatever the module
	// reports, never empty or the placeholder "(devel)".
	version = "devel"
	got := resolvedVersion()
	if got == "" || got == "(devel)" {
		t.Errorf("unstamped: resolvedVersion() = %q", got)
	}
}

func TestVersionFlag(t *testing.T) {
	t.Cleanup(func() { version = "devel" })
	version = "v1.2.3"
	rootCmd.Version = resolvedVersion()

	var out strings.Builder
	rootCmd.SetOut(&out)
	rootCmd.SetArgs([]string{"--version"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	if err := rootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "slsa-verifier version v1.2.3") {
		t.Errorf("--version printed %q", out.String())
	}
}
