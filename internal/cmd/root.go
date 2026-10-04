// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// Exit codes the CLI uses for the verify subcommand.
const (
	ExitOK              = 0
	ExitVerifyFailed    = 1
	ExitExecutionFailed = 2
)

// ErrVerifyFailed signals that the verifier ran successfully but the
// attestation did not pass. Returning it from RunE causes Execute to exit
// with ExitVerifyFailed without printing the usual "Error:" prefix.
var ErrVerifyFailed = errors.New("attestation verification failed")

const appname = "slsa-verifier"

// version is the release this binary was built from. Releases set it at
// build time (-ldflags, see .goreleaser.yaml); a binary built with
// `go install module@version` reads it from the module information instead,
// and anything else reports "devel".
var version = "devel"

// resolvedVersion is what --version prints.
func resolvedVersion() string {
	if version != "devel" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}

var rootCmd = &cobra.Command{
	Short: fmt.Sprintf("%s: verify SLSA build and source attestations", appname),
	Long: fmt.Sprintf(`
%s verifies SLSA build attestations (v0.1, v0.2, v1.0) and SLSA source
attestations against the SLSA spec-defined controls and any user-supplied
controls.
`, appname),
	Use:           appname,
	Version:       resolvedVersion(),
	SilenceUsage:  false,
	SilenceErrors: true,
}

// Execute runs the CLI. The CLI translates verifier outcomes to exit
// codes: 0 for pass, 1 for verification failure, 2 for execution errors.
func Execute() {
	shared := &sharedOptions{}
	shared.AddFlags(rootCmd)
	addBuild(rootCmd, shared)
	addVSA(rootCmd, shared)
	addSource(rootCmd, shared)
	if err := rootCmd.Execute(); err != nil {
		if errors.Is(err, ErrVerifyFailed) {
			os.Exit(ExitVerifyFailed)
		}
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(ExitExecutionFailed)
	}
}
