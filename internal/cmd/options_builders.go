// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/slsa-framework/verifier/pkg/slsa/builders"
)

// builderOptions holds the flags that bind builders to the identities
// signing their provenance: bindings given on the command line and a
// registry file extending the embedded one.
type builderOptions struct {
	// BuilderSpecs holds the raw --builder values, "id=signer-spec" or
	// "id=issuer".
	BuilderSpecs []string

	// RegistryPath is a registry file or directory (--builders) merged
	// over the embedded registry.
	RegistryPath string

	// registry is the merged registry, nil when nothing extends the
	// embedded one. Populated by Validate.
	registry *builders.Registry

	// LevelSpecs holds the raw --builder-level values, "id=level".
	LevelSpecs []string

	// levels are the parsed builder levels, nil when none were given.
	// Populated by Validate.
	levels map[string]int
}

func (o *builderOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringArrayVar(
		&o.BuilderSpecs, "builder", nil,
		"builder bound to the identity signing its provenance, as id=<signer spec> or "+
			"id=<OIDC issuer> (repeatable; extends the embedded registry)",
	)
	cmd.PersistentFlags().StringVar(
		&o.RegistryPath, "builders", "",
		"YAML file or directory of builder bindings, merged over the embedded registry",
	)
	cmd.PersistentFlags().StringArrayVar(
		&o.LevelSpecs, "builder-level", nil,
		"highest SLSA build level a builder reaches, as id=level (eg 1 or SLSA_BUILD_LEVEL_1); "+
			"caps the computed level of its provenance (repeatable)",
	)
}

// Validate parses the bindings and loads the registry file, building
// the merged registry when either was given.
func (o *builderOptions) Validate() error {
	levels, err := parseBuilderLevels(o.LevelSpecs)
	o.levels = levels
	if len(o.BuilderSpecs) == 0 && o.RegistryPath == "" {
		o.registry = nil
		return err
	}
	reg, err := builders.LoadEmbedded()
	if err != nil {
		return fmt.Errorf("loading the embedded builder registry: %w", err)
	}
	var errs []error
	if o.RegistryPath != "" {
		custom, err := builders.Load(o.RegistryPath)
		if err != nil {
			errs = append(errs, fmt.Errorf("--builders: %w", err))
		} else if err := reg.Merge(custom); err != nil {
			errs = append(errs, fmt.Errorf("--builders: %w", err))
		}
	}
	for _, raw := range o.BuilderSpecs {
		b, err := builders.ParseBinding(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("--builder: %w", err))
			continue
		}
		if err := reg.Add(b); err != nil {
			errs = append(errs, fmt.Errorf("--builder %q: %w", raw, err))
		}
	}
	if err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	o.registry = reg
	return nil
}

// parseBuilderLevels parses --builder-level values. The level follows the
// last =, since builder ids are URIs.
func parseBuilderLevels(specs []string) (map[string]int, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	levels := make(map[string]int, len(specs))
	var errs []error
	for _, raw := range specs {
		i := strings.LastIndex(raw, "=")
		if i <= 0 {
			errs = append(errs, fmt.Errorf("--builder-level %q: want id=level", raw))
			continue
		}
		level, err := parseBuildLevel(raw[i+1:])
		if err == nil && level < 1 {
			err = fmt.Errorf("builder level %q must be at least 1", raw[i+1:])
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("--builder-level %q: %w", raw, err))
			continue
		}
		levels[raw[:i]] = level
	}
	return levels, errors.Join(errs...)
}

// Levels returns the parsed builder levels, nil when none were given.
func (o *builderOptions) Levels() map[string]int {
	return o.levels
}

// Registry returns the merged builder registry, or nil to use the
// embedded one.
func (o *builderOptions) Registry() *builders.Registry {
	return o.registry
}
