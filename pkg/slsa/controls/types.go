// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package controls

import (
	"errors"
	"fmt"
)

// Track names a SLSA spec track. Every control declares the track it
// targets via its `track` field; the catalog assembles the
// predicate-type → track mapping from those declarations rather than a
// hard-coded list.
type Track string

const (
	TrackBuild  Track = "build"
	TrackSource Track = "source"
)

// Control models a single verification control: a labelled bundle of CEL
// checks, each pinned to a specific predicate type.
//
// Track names the SLSA spec track this control targets ("build" or
// "source"). Every check's predicateType must belong to a predicate
// type registered under the same track — the load-time cross-validation
// in the embed loader rejects misclassified controls.
type Control struct {
	ID          string  `yaml:"id"`
	Title       string  `yaml:"title"`
	Description string  `yaml:"description,omitempty"`
	Track       string  `yaml:"track"`
	SLSALevel   int     `yaml:"slsaLevel,omitempty"`
	Checks      []Check `yaml:"checks"`
}

// Check binds a CEL expression to a specific in-toto predicate type along
// with the names of parameters the expression expects to find on `params`.
//
// Parameters lists params the expression requires: evaluating the check
// without one of them is an error. OptionalParameters lists params the
// expression needs to run but that the caller may legitimately omit:
// when one is missing the check is skipped instead of erroring, so the
// control drops out of the roster without failing verification.
//
// BuildTypes, when set, narrows the check further to only fire when the
// statement's build provenance buildType is one of the listed URIs
// (OR-matched, exact). It is intended for controls under the
// build/buildType catalog category that are specific to one or more
// builders. Leaving it empty makes the check apply to any buildType
// whose predicateType matches.
type Check struct {
	PredicateType      string   `yaml:"predicateType"`
	Expression         string   `yaml:"expression"`
	Parameters         []string `yaml:"parameters,omitempty"`
	OptionalParameters []string `yaml:"optionalParameters,omitempty"`
	BuildTypes         []string `yaml:"buildTypes,omitempty"`
}

// Validate checks the control's structural integrity. Cross-validation
// against the eval predicate registry (track ↔ check.predicateType
// match) lives in the loader so this package can stay leaf-level.
func (c *Control) Validate() error {
	var errs []error
	if c.ID == "" {
		errs = append(errs, errors.New("control: id is required"))
	}
	if c.Title == "" {
		errs = append(errs, fmt.Errorf("control %q: title is required", c.ID))
	}
	if c.Track == "" {
		errs = append(errs, fmt.Errorf("control %q: track is required", c.ID))
	}
	if len(c.Checks) == 0 {
		errs = append(errs, fmt.Errorf("control %q: at least one check is required", c.ID))
	}
	for i := range c.Checks {
		if err := c.Checks[i].Validate(); err != nil {
			errs = append(errs, fmt.Errorf("control %q check #%d: %w", c.ID, i, err))
		}
	}
	return errors.Join(errs...)
}

// Validate checks the check's structural integrity.
func (c *Check) Validate() error {
	var errs []error
	if c.PredicateType == "" {
		errs = append(errs, errors.New("predicateType is required"))
	}
	if c.Expression == "" {
		errs = append(errs, errors.New("expression is required"))
	}
	return errors.Join(errs...)
}
