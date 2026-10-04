// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/spf13/cobra"
)

// defaultVerifierID is the verifier.id recorded in the VSAs this tool
// emits unless --verifier-id says otherwise. It identifies the SLSA
// verifier project as the entity that produced the summary; operators
// running the tool as their own verifier name themselves instead, since
// that is the id their consumers bind to their signing identity.
const defaultVerifierID = "https://github.com/slsa-framework/verifier"

// vsaOutputOptions is the OptionsSet shared by the verifier subcommands
// (build and source) that can summarise their own evaluation as a SLSA
// Verification Summary Attestation. When EmitVSA is set, the command
// writes an unsigned VSA carrying the computed SLSA level to stdout
// instead of the human-readable control roster.
type vsaOutputOptions struct {
	// EmitVSA toggles emission of an unsigned VSA to stdout (--vsa).
	EmitVSA bool

	// VerifierID is the verifier.id the emitted VSA names as its issuer
	// (--verifier-id). Defaults to this project's URL.
	VerifierID string
}

func (o *vsaOutputOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(
		&o.EmitVSA, "vsa", false,
		"emit an unsigned Verification Summary Attestation (VSA) with the computed SLSA levels",
	)
	cmd.PersistentFlags().StringVar(
		&o.VerifierID, "verifier-id", defaultVerifierID,
		"verifier.id to record in the emitted VSA",
	)
}

// Validate fills in the default verifier id when none was given, so
// options built without binding the flags behave like the command.
func (o *vsaOutputOptions) Validate() error {
	if o.VerifierID == "" {
		o.VerifierID = defaultVerifierID
	}
	return nil
}
