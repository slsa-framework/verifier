// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"

	"github.com/carabiner-dev/command"
	sapi "github.com/policylabs/signer/api/v1"
	"github.com/spf13/cobra"
)

var _ command.OptionsSet = &signingOptions{}

// signingOptions exposes --signer (repeatable, takes a signer/api/v1
// spec string). Supplying any --signer implies that signatures are
// required; subcommands that embed this set must propagate that to
// sharedOptions.RequireSignatures during their own Validate.
type signingOptions struct {
	config *command.OptionsSetConfig

	// SignerSpecs is the raw --signer flag values from the command line.
	SignerSpecs []string

	// Signers is the parsed signer-identity list (one *sapi.Identity per
	// --signer flag). Populated by Validate.
	Signers []*sapi.Identity
}

func (so *signingOptions) Config() *command.OptionsSetConfig {
	if so.config == nil {
		so.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{
				"signer": {
					Long: "signer",
					Help: "expected signer identities (spec strings)",
				},
			},
		}
	}
	return so.config
}

func (so *signingOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringArrayVar(
		&so.SignerSpecs,
		so.Config().LongFlag("signer"),
		nil,
		so.Config().HelpText("signer"),
	)
}

func (so *signingOptions) Validate() error {
	errs := []error{}
	for _, spec := range so.SignerSpecs {
		id, err := sapi.NewIdentityFromSpec(spec)
		if err != nil {
			errs = append(errs, fmt.Errorf("parsing --signer %q: %w", spec, err))
			continue
		}
		so.Signers = append(so.Signers, id)
	}
	return errors.Join(errs...)
}
