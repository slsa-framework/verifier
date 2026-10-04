// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/policylabs/attestation"
	"github.com/spf13/cobra"

	"github.com/slsa-framework/verifier/pkg/subject"
)

// subjectOptions binds a verification to the artifacts the user holds:
// files given as positional arguments after the attestation, and
// digests given with -s/--subject as algorithm:digest. When any are
// given, the attestation must be about every one of them.
type subjectOptions struct {
	// SubjectSpecs holds the raw -s/--subject values.
	SubjectSpecs []string

	// ArtifactPaths holds the artifact files given as positional
	// arguments. They are hashed with the digest algorithms the
	// attestation's subjects use.
	ArtifactPaths []string

	// Subjects holds the parsed --subject values. Populated by Validate.
	Subjects []*subject.Expected
}

func (o *subjectOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringArrayVarP(
		&o.SubjectSpecs, "subject", "s", nil,
		"expected subject as algorithm:digest, eg sha256:<hex> (repeatable)",
	)
}

func (o *subjectOptions) Validate() error {
	errs := []error{}
	o.Subjects = nil
	for _, spec := range o.SubjectSpecs {
		expected, err := subject.Parse(spec)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		o.Subjects = append(o.Subjects, expected)
	}
	for _, path := range o.ArtifactPaths {
		info, err := os.Stat(path)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("artifact %s: %w", path, err))
		case info.IsDir():
			errs = append(errs, fmt.Errorf("artifact %s is a directory", path))
		}
	}
	return errors.Join(errs...)
}

// expects reports whether any subject or artifact was given.
func (o *subjectOptions) expects() bool {
	return len(o.Subjects) > 0 || len(o.ArtifactPaths) > 0
}

// resolve returns every expected subject: the artifact files, hashed
// with the digest algorithms the statement's subjects use, followed by
// the --subject values. Files cannot be checked against subjects that
// carry no content digest (gitCommit, dirHash, etc): that is an error
// naming what the subjects use, not a silent pass.
func (o *subjectOptions) resolve(stmt attestation.Statement) ([]*subject.Expected, error) {
	if !o.expects() {
		return nil, nil
	}
	var expected []*subject.Expected
	if len(o.ArtifactPaths) > 0 {
		if stmt == nil {
			return nil, errors.New("cannot hash artifacts: the attestation produced no statement")
		}
		hashable, other := subject.Algorithms(stmt.GetSubjects())
		if len(hashable) == 0 {
			if len(other) == 0 {
				return nil, errors.New("cannot check artifact files: the attestation has no subjects with digests")
			}
			return nil, fmt.Errorf(
				"cannot check artifact files against this attestation: its subjects only carry %s digests, which are not hashes of file contents (use --subject to state one)",
				strings.Join(other, ", "),
			)
		}
		hashed, err := subject.HashFiles(o.ArtifactPaths, hashable)
		if err != nil {
			return nil, err
		}
		expected = append(expected, hashed...)
	}
	return append(expected, o.Subjects...), nil
}
