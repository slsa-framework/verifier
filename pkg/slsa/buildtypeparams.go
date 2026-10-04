// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package slsa

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/policylabs/attestation"

	"github.com/slsa-framework/verifier/pkg/slsa/controls"
	"github.com/slsa-framework/verifier/pkg/slsa/eval"
)

// ErrBuildTypeParamsUnset is returned by Verify when the catalog has
// checks for the statement's buildType that take parameters and the
// caller set none of them: the catalog knows how to check this builder's
// provenance and no expectation was stated. Set at least one of the
// listed parameters, or skip the buildType checks explicitly.
var ErrBuildTypeParamsUnset = errors.New("buildType checks need parameters that were not set")

// BuildTypeParamsUnsetError carries the detail behind
// ErrBuildTypeParamsUnset: the buildType and, per control, the
// parameters its applicable check accepts.
type BuildTypeParamsUnsetError struct {
	BuildType string
	Controls  []UnconfiguredControl
}

// UnconfiguredControl is a buildType control whose check applies to the
// statement but has none of its parameters set.
type UnconfiguredControl struct {
	ID                 string
	Title              string
	Parameters         []string
	OptionalParameters []string
}

func (e *BuildTypeParamsUnsetError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "the attestation's buildType %s has checks that need parameters which were not set:\n", e.BuildType)
	for _, c := range e.Controls {
		fmt.Fprintf(&b, "  %s (%s):", c.ID, c.Title)
		for _, p := range c.Parameters {
			fmt.Fprintf(&b, " %s", p)
		}
		for _, p := range c.OptionalParameters {
			fmt.Fprintf(&b, " %s (optional)", p)
		}
		b.WriteString("\n")
	}
	b.WriteString("set them with --param name:value, or pass --skip-buildtype-checks to skip these checks")
	return b.String()
}

func (e *BuildTypeParamsUnsetError) Unwrap() error { return ErrBuildTypeParamsUnset }

// applicableCheck returns the check in c that applies to the statement's
// predicate type and buildType, following the same rule evaluateControl
// uses to pick one, or nil when none applies.
func applicableCheck(c *controls.Control, predicateType, buildType string) *controls.Check {
	for i := range c.Checks {
		ck := &c.Checks[i]
		if ck.PredicateType != predicateType {
			continue
		}
		if len(ck.BuildTypes) > 0 && !slices.Contains(ck.BuildTypes, buildType) {
			continue
		}
		return ck
	}
	return nil
}

// partitionBuildTypeControls decides which buildType controls run. A
// control whose applicable check declares parameters and has none of
// them set is unconfigured. When no parameter of any applicable check is
// set at all, the caller stated no expectation for a builder the catalog
// knows: that is an error unless opts.SkipBuildTypeChecks, in which case
// unconfigured controls are skipped instead of run. Controls without
// parameters, and controls with at least one parameter set, always run.
func partitionBuildTypeControls(
	opts *VerificationOptions, ctrls []*controls.Control, stmt attestation.Statement,
) (run []*controls.Control, skipped []*ControlResult, err error) {
	if len(ctrls) == 0 {
		return nil, nil, nil
	}
	predicate, err := extractPredicate(stmt)
	if err != nil {
		return nil, nil, err
	}
	predicateType := string(stmt.GetPredicateType())
	buildType := eval.BuildTypeOf(predicate)

	unconfigured := make([]UnconfiguredControl, 0, len(ctrls))
	run = make([]*controls.Control, 0, len(ctrls))
	anySet := false
	for _, c := range ctrls {
		ck := applicableCheck(c, predicateType, buildType)
		if ck == nil || (len(ck.Parameters) == 0 && len(ck.OptionalParameters) == 0) {
			run = append(run, c)
			continue
		}
		set := false
		for _, p := range slices.Concat(ck.Parameters, ck.OptionalParameters) {
			if _, ok := opts.Params[p]; ok {
				set = true
				break
			}
		}
		if set {
			anySet = true
			run = append(run, c)
			continue
		}
		unconfigured = append(unconfigured, UnconfiguredControl{
			ID: c.ID, Title: c.Title,
			Parameters:         slices.Clone(ck.Parameters),
			OptionalParameters: slices.Clone(ck.OptionalParameters),
		})
	}
	if len(unconfigured) == 0 {
		return run, nil, nil
	}
	sort.Slice(unconfigured, func(i, j int) bool { return unconfigured[i].ID < unconfigured[j].ID })

	if !anySet && !opts.SkipBuildTypeChecks {
		return nil, nil, &BuildTypeParamsUnsetError{BuildType: buildType, Controls: unconfigured}
	}
	if !opts.SkipBuildTypeChecks {
		// Some expectation was stated: unconfigured controls run and
		// report their own missing or optional parameters.
		for _, u := range unconfigured {
			for _, c := range ctrls {
				if c.ID == u.ID {
					run = append(run, c)
				}
			}
		}
		return run, nil, nil
	}
	for _, u := range unconfigured {
		for _, c := range ctrls {
			if c.ID == u.ID {
				skipped = append(skipped, &ControlResult{
					ID: c.ID, Title: c.Title, SLSALevel: c.SLSALevel, Status: StatusSkipped,
					Message: fmt.Sprintf("skipped: parameters not set (%s)", strings.Join(slices.Concat(u.Parameters, u.OptionalParameters), ", ")),
				})
			}
		}
	}
	return run, skipped, nil
}
