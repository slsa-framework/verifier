// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	signeroptions "github.com/carabiner-dev/signer/options"
	"github.com/spf13/cobra"

	"github.com/slsa-framework/verifier/pkg/attestation"
	"github.com/slsa-framework/verifier/pkg/slsa"
	"github.com/slsa-framework/verifier/pkg/slsa/controls"
)

// buildOptions composes every OptionsSet needed by the build command.
// The shared flags (--param, --key, --require-signatures) come from
// sharedOptions registered on the root command, this struct only owns
// the build-specific flags.
type buildOptions struct {
	shared *sharedOptions

	signingOptions
	controlsOptions
	vsaOutputOptions
	subjectOptions
	builderOptions

	// AttestationPath is the first positional argument: path to the
	// attestation file (plain in-toto statement, DSSE envelope, or
	// Sigstore bundle). Any further positional arguments are artifact
	// files the attestation must be about (see subjectOptions).
	AttestationPath string

	// SkipBuildTypeChecks skips buildType checks whose parameters were
	// not set instead of refusing to run (--skip-buildtype-checks).
	SkipBuildTypeChecks bool

	// Level is the raw --level flag: the SLSA build level the
	// attestation is required to reach, as a bare number or a
	// SLSA_BUILD_LEVEL_N string. Parsed into MinLevel by Validate.
	Level string

	// MinLevel is the parsed required level. With it set, controls
	// above it are informative: they cap the computed level without
	// failing the run. Zero requires every applicable control to pass.
	MinLevel int

	// Spec is the SLSA spec version whose criteria the attestation is
	// verified against, empty means the latest the catalog defines.
	Spec string

	// Verbose toggles inclusion of skipped controls and control titles in
	// the verify summary roster.
	Verbose bool
}

// AddFlags registers the build-specific flags on cmd.
func (o *buildOptions) AddFlags(cmd *cobra.Command) {
	o.signingOptions.AddFlags(cmd)
	o.controlsOptions.AddFlags(cmd)
	o.vsaOutputOptions.AddFlags(cmd)
	o.subjectOptions.AddFlags(cmd)
	o.builderOptions.AddFlags(cmd)
	cmd.PersistentFlags().BoolVar(
		&o.SkipBuildTypeChecks, "skip-buildtype-checks", false,
		"skip the buildType-specific checks whose parameters were not set, instead of "+
			"refusing to run until at least one of them is",
	)
	cmd.PersistentFlags().StringVar(
		&o.Level, "level", "0",
		"required SLSA build level, 1-3 (eg 2 or SLSA_BUILD_LEVEL_2); controls above it are "+
			"informative and only cap the computed level. 0 requires every applicable control to pass",
	)
	cmd.PersistentFlags().StringVar(
		&o.Spec, "spec", "",
		"SLSA spec version to verify against (eg 1.2) defaults to latest",
	)
	cmd.PersistentFlags().BoolVarP(
		&o.Verbose, "verbose", "v", false,
		"show skipped controls and control titles in the summary",
	)
}

// Validate runs every option set's validator and propagates implications
// to the shared options struct.
func (o *buildOptions) Validate() error {
	errs := []error{
		o.shared.Validate(),
		o.signingOptions.Validate(),
		o.controlsOptions.Validate(),
		o.vsaOutputOptions.Validate(),
		o.subjectOptions.Validate(),
		o.builderOptions.Validate(),
	}
	if err := checkAttestationPath(o.AttestationPath); err != nil {
		errs = append(errs, err)
	}
	level, err := parseBuildLevel(o.Level)
	if err != nil {
		errs = append(errs, err)
	}
	o.MinLevel = level
	// --signer implies --require-signatures: matching an identity on an
	// unsigned statement is meaningless.
	if len(o.Signers) > 0 {
		o.shared.RequireSignatures = true
	}
	return errors.Join(errs...)
}

const maxBuildLevel = 3

// parseBuildLevel parses a --level value: a bare number or a
// SLSA_BUILD_LEVEL_N string; 0 and the empty string mean no minimum.
func parseBuildLevel(value string) (int, error) {
	if strings.TrimSpace(value) == "" {
		return 0, nil
	}
	trimmed := strings.TrimPrefix(
		strings.ToUpper(strings.TrimSpace(value)), "SLSA_BUILD_LEVEL_",
	)
	level, err := strconv.Atoi(trimmed)
	if err != nil || level < 0 || level > maxBuildLevel {
		return 0, fmt.Errorf("invalid build level %q (want 0-%d or SLSA_BUILD_LEVEL_N)", value, maxBuildLevel)
	}
	return level, nil
}

// addBuild registers the build subcommand on parentCmd.
func addBuild(parentCmd *cobra.Command, shared *sharedOptions) {
	opts := &buildOptions{shared: shared}
	buildCmd := &cobra.Command{
		Short: "Verify a SLSA build attestation",
		Long: `Verify a SLSA build attestation against the SLSA spec-defined
build-track controls and any user-supplied controls.

The attestation may be supplied as a plain in-toto statement, a DSSE
envelope (signed with one or more keys via --key), or a Sigstore
bundle.

Signer identities (--signer) are spec strings of the form
sigstore::<issuer>::<identity>, matched exactly, or
sigstore(identityMatch=regex)::<issuer>::<identity-regexp>:

  sigstore::https://accounts.google.com::user@example.com
  sigstore(identityMatch=regex)::https://token.actions.githubusercontent.com::.*@example/.*

Artifact files given after the attestation are hashed with the digest
algorithms its subjects use, and --subject states a digest directly;
the attestation must be about every one of them or the verification
fails. Without any, the attestation is verified on its content alone.

A signed attestation's builder.id is bound to the identity that signed
it through the builder registry, which knows the slsa-github-generator
builders, the SLSA build attester observing runs from its reusable
workflow, and any GitHub Actions workflow signing its own provenance.
Bind a builder of your own with --builder <id>=<signer spec> (or
<id>=<OIDC issuer>, for workflow-style identities whose subject is the
builder id) or a registry file passed with --builders; naming the
signer you expect with --signer binds whatever builder it signs for.
A signed attestation whose builder nothing binds still verifies, with
builder.id reported as unproven.`,
		Use: "build <attestation-path> [artifact...]",
		Example: fmt.Sprintf(`  # Verify provenance from the slsa-github-generator
  %[1]s build --param expected_source:github.com/example/repo \
      --param trusted_builders:[https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0] \
      --param expected_tag:v1.2.3 provenance.intoto.jsonl app.tgz

  # Bind a builder of your own to the identity that signs for it
  %[1]s build --param expected_source:github.com/example/repo \
      --param trusted_builders:[https://ci.example.com/builder] \
      --builder https://ci.example.com/builder=spiffe://example.com/ci/builder \
      --skip-buildtype-checks provenance.dsse.json`, appname),
		SilenceUsage:  false,
		SilenceErrors: true,
		Args:          cobra.MinimumNArgs(1),
		PreRunE: func(_ *cobra.Command, args []string) error {
			opts.AttestationPath = args[0]
			opts.ArtifactPaths = args[1:]
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}
			cmd.SilenceUsage = true
			return runBuild(cmd, opts)
		},
	}
	opts.AddFlags(buildCmd)
	parentCmd.AddCommand(buildCmd)
}

func runBuild(cmd *cobra.Command, opts *buildOptions) error {
	keys, err := opts.shared.ParseKeys()
	if err != nil {
		return fmt.Errorf("parsing keys: %w", err)
	}

	// The file may hold several attestations (a release's attestations
	// file, a commit's git note): pick the build provenance, about the
	// stated subjects when any were given.
	env, err := loadEnvelope(cmd.Context(), opts.AttestationPath, &attestation.Selection{
		Kind:               "build provenance",
		PredicateTypes:     buildPredicateTypes,
		Subjects:           opts.Subjects,
		NoGitDigestAliases: !opts.shared.GitDigestAliases,
	})
	if err != nil {
		return err
	}

	// Verify envelope signatures. Bare envelopes are unsigned and Verify
	// is a no-op for them. DSSE uses keys and Sigstore bundles verify
	// against the embedded trust root.
	if err := env.Verify(keys,
		signeroptions.WithRekorVerification(true),
		signeroptions.WithRekorURL(opts.shared.RekorURL),
	); err != nil {
		return fmt.Errorf("verifying envelope signatures: %w", err)
	}

	stmt := env.GetStatement()
	if stmt == nil {
		return errors.New("envelope produced no statement")
	}

	// Artifacts are hashed with the digest algorithms the attestation's
	// subjects use, so the comparison is on the attestation's terms.
	expected, err := opts.resolve(stmt)
	if err != nil {
		return err
	}

	var verifierOpts []slsa.Option
	if reg := opts.Registry(); reg != nil {
		verifierOpts = append(verifierOpts, slsa.WithBuilders(reg))
	}
	v, err := slsa.New(verifierOpts...)
	if err != nil {
		return fmt.Errorf("building verifier: %w", err)
	}

	result, err := v.Verify(
		cmd.Context(),
		stmt,
		slsa.WithSubjects(expected),
		slsa.WithGitDigestAliases(opts.shared.GitDigestAliases),
		slsa.WithSkipBuildTypeChecks(opts.SkipBuildTypeChecks),
		slsa.WithParams(opts.shared.Params),
		slsa.WithRequireSignatures(opts.shared.RequireSignatures),
		slsa.WithExpectedSigners(opts.Signers),
		slsa.WithUserControlList(opts.Controls),
		slsa.WithTrack(controls.TrackBuild),
		slsa.WithSpecVersion(opts.Spec),
		slsa.WithMinLevel(opts.MinLevel),
		slsa.WithVerifierID(opts.VerifierID),
	)
	// Signature/identity failures from the verification layer are a
	// verification outcome (exit 1), not an execution failure (exit 2).
	if errors.Is(err, slsa.ErrSignatureUnverified) {
		writef(cmd.OutOrStdout(), "FAIL\n  Signature: %s\n", err)
		return ErrVerifyFailed
	}
	if errors.Is(err, slsa.ErrSignatureRequired) {
		writef(cmd.OutOrStdout(), "FAIL\n  Signature: %s\n", err)
		return ErrVerifyFailed
	}
	if errors.Is(err, slsa.ErrIdentityMismatch) {
		writef(cmd.OutOrStdout(), "FAIL\n  Identity: %s\n", err)
		return ErrVerifyFailed
	}
	// An incomplete invocation, not a verification outcome: the message
	// already says what to set, so surface it as is.
	if errors.Is(err, slsa.ErrBuildTypeParamsUnset) {
		return err
	}
	if err != nil {
		return fmt.Errorf("running verification: %w", err)
	}

	// With --vsa, stdout carries the unsigned VSA JSON instead of the
	// human-readable roster so it can be piped or stored directly.
	if opts.EmitVSA {
		if err := emitVSA(cmd.OutOrStdout(), stmt, result, controls.TrackBuild); err != nil {
			return fmt.Errorf("emitting VSA: %w", err)
		}
	} else {
		printResult(cmd.OutOrStdout(), result, opts.Verbose)
	}
	if !result.Pass() {
		return ErrVerifyFailed
	}
	return nil
}

// writef wraps Fprintf and discards the result
func writef(w io.Writer, format string, args ...any) {
	fmt.Fprintf(w, format, args...) //nolint:errcheck
}
