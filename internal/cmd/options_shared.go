// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"

	"github.com/carabiner-dev/command/keys"
	signeroptions "github.com/policylabs/signer/options"
	"github.com/spf13/cobra"
)

// sharedOptions aggregates the flags every verifier subcommand
// (build, vsa, source) exposes: --param, --key, and
// --require-signatures. They are registered as persistent flags on
// the root command so each subcommand reads the same parsed values.
type sharedOptions struct {
	paramOptions
	keys.Options

	// RequireSignatures, when true, fails verification if the statement
	// is unsigned or its signature did not verify. A signed statement
	// the verifier has no key or trust material to check is reported
	// as an execution error rather than a failed verification.
	RequireSignatures bool

	// GitDigestAliases makes git object digests (gitCommit and friends)
	// interchangeable with the sha1 or sha256 hash they are when the
	// attestation is bound to subjects. On by default;
	// --git-digest-aliases=false requires the exact algorithm names.
	GitDigestAliases bool

	// RekorURL is the transparency log queried to verify keyless DSSE
	// envelopes (--rekor-url). The lookup itself is always on; an
	// unreachable log leaves such envelopes unverifiable.
	RekorURL string
}

func (so *sharedOptions) AddFlags(cmd *cobra.Command) {
	so.paramOptions.AddFlags(cmd)
	so.Options.AddFlags(cmd)
	cmd.PersistentFlags().BoolVar(
		&so.RequireSignatures, "require-signatures", false,
		"fail verification if the statement is unsigned or its signature did not verify",
	)
	cmd.PersistentFlags().StringVar(
		&so.RekorURL, "rekor-url", signeroptions.DefaultRekorURL,
		"transparency log for verifying keyless DSSE envelopes; looked up by default, "+
			"an unreachable log leaves them unverifiable",
	)
	cmd.PersistentFlags().BoolVar(
		&so.GitDigestAliases, "git-digest-aliases", true,
		"treat gitCommit and other git digests as the hash they are",
	)
}

func (so *sharedOptions) Validate() error {
	return errors.Join(
		so.paramOptions.Validate(),
		so.Options.Validate(),
	)
}
