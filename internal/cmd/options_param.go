// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/csv"
	"errors"
	"fmt"
	"strings"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"
)

var _ command.OptionsSet = &paramOptions{}

// paramOptions is the OptionsSet that exposes the -p/--param flag and
// parses its values into a name → any map for the verifier.
type paramOptions struct {
	config *command.OptionsSetConfig

	// Raw holds the unparsed --param flag values as supplied on the
	// command line. Populated by cobra; turned into Params by Validate.
	Raw []string

	// Params holds the parsed values keyed by name. String values stay
	// as string; bracketed list values become []string.
	Params map[string]any
}

// Config returns the flag configuration.
func (po *paramOptions) Config() *command.OptionsSetConfig {
	if po.config == nil {
		po.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{
				"param": {
					Short: "p",
					Long:  "param",
					Help:  "control parameter as name:value or name:[v1, v2] (repeatable)",
				},
			},
		}
	}
	return po.config
}

// AddFlags registers --param/-p on cmd. StringArrayVarP is used (not
// StringSliceVarP) so commas inside list values are preserved.
func (po *paramOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringArrayVarP(
		&po.Raw,
		po.Config().LongFlag("param"),
		po.Config().ShortFlag("param"),
		nil,
		po.Config().HelpText("param"),
	)
}

// Validate parses every --param entry into the Params map. Params is
// always usable afterwards, even when an entry fails to parse: the
// subcommands' validators collect errors rather than stop at the
// first one, and they write their own flag-derived params into the
// map before the errors are reported.
func (po *paramOptions) Validate() error {
	po.Params = map[string]any{}
	parsed, err := parseParams(po.Raw)
	if err != nil {
		return err
	}
	po.Params = parsed
	return nil
}

// parseParams parses a slice of raw --param strings into a name → value
// map.
func parseParams(raw []string) (map[string]any, error) {
	out := make(map[string]any, len(raw))
	for _, p := range raw {
		name, value, err := parseParam(p)
		if err != nil {
			return nil, fmt.Errorf("invalid param %q: %w", p, err)
		}
		out[name] = value
	}
	return out, nil
}

// parseParam splits a single name:value string. When the value is wrapped
// in [ ] it is returned as []string parsed as CSV; otherwise it is the
// raw string after the first colon.
func parseParam(input string) (name string, value any, err error) {
	idx := strings.Index(input, ":")
	if idx < 0 {
		return "", nil, errors.New("missing ':' separator between name and value")
	}
	name = strings.TrimSpace(input[:idx])
	raw := strings.TrimSpace(input[idx+1:])
	if name == "" {
		return "", nil, errors.New("empty parameter name")
	}

	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		items, lerr := parseList(raw[1 : len(raw)-1])
		if lerr != nil {
			return "", nil, fmt.Errorf("parsing list value: %w", lerr)
		}
		return name, items, nil
	}
	return name, raw, nil
}

// parseList splits a CSV string supporting double-quoted fields (so list
// items can contain commas when quoted).
func parseList(s string) ([]string, error) {
	r := csv.NewReader(strings.NewReader(s))
	r.LazyQuotes = true
	r.TrimLeadingSpace = true
	rec, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("reading CSV list: %w", err)
	}
	return rec, nil
}
