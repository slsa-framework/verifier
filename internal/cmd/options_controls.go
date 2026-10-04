// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"

	"github.com/slsa-framework/verifier/pkg/slsa/controls"
)

var _ command.OptionsSet = &controlsOptions{}

// controlsOptions exposes --controls/-c for loading user-supplied control
// definitions from a YAML file or a directory of YAML files. The user's
// controls run alongside the embedded SLSA core controls under the
// verifier's user layer.
type controlsOptions struct {
	config *command.OptionsSetConfig

	// Path is the YAML file or directory passed via --controls.
	Path string

	// Controls is the list parsed from Path during Validate.
	Controls []*controls.Control
}

func (co *controlsOptions) Config() *command.OptionsSetConfig {
	if co.config == nil {
		co.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{
				"controls": {
					Short: "c",
					Long:  "controls",
					Help:  "path to a YAML file or directory of user-supplied controls",
				},
			},
		}
	}
	return co.config
}

func (co *controlsOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(
		&co.Path,
		co.Config().LongFlag("controls"),
		co.Config().ShortFlag("controls"),
		"",
		co.Config().HelpText("controls"),
	)
}

func (co *controlsOptions) Validate() error {
	if co.Path == "" {
		return nil
	}
	ctrls, err := controls.Load(co.Path)
	if err != nil {
		return fmt.Errorf("loading user controls: %w", err)
	}
	co.Controls = ctrls
	return nil
}
