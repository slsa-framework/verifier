// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	sapi "github.com/carabiner-dev/signer/api/v1"
	signeroptions "github.com/carabiner-dev/signer/options"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/spf13/cobra"

	"github.com/slsa-framework/verifier/pkg/attestation"
	"github.com/slsa-framework/verifier/pkg/slsa"
	"github.com/slsa-framework/verifier/pkg/slsa/controls"
	"github.com/slsa-framework/verifier/pkg/subject"
)

// officialSourceIssuer is the OIDC issuer of the certificates GitHub
// Actions workflows sign with.
const officialSourceIssuer = "https://token.actions.githubusercontent.com"

// officialSourceSigners are the identity specs of the official SLSA
// source workflow that signs source provenance attestations. The
// workflow lives in slsa-framework/actions and its callers pin it to a
// release digest or tag, so its identity is matched up to the ref. The
// identities of the repositories that hosted the workflow before, where
// it always ran from main, are accepted for attestations issued while
// it lived there. Verifying against them is opt-in via --official.
var officialSourceSigners = []string{
	"sigstore(identityMatch=prefix)::" + officialSourceIssuer + "::https://github.com/slsa-framework/actions/.github/workflows/compute_slsa_source.yml@",
	"sigstore::" + officialSourceIssuer + "::https://github.com/slsa-framework/source-actions/.github/workflows/compute_slsa_source.yml@refs/heads/main",
	"sigstore::" + officialSourceIssuer + "::https://github.com/slsa-framework/slsa-source-poc/.github/workflows/compute_slsa_source.yml@refs/heads/main",
}

// sourceOptions composes the OptionsSets the source command exposes. The
// shared flags (--param, --key, --require-signatures) come from
// sharedOptions registered on the root command, this struct only owns
// the source-specific flags.
type sourceOptions struct {
	shared *sharedOptions

	signingOptions
	controlsOptions
	vsaOutputOptions

	// SubjectSpec is the raw --subject value: the commit the attestation
	// must be about, as algorithm:digest or a bare 40-character commit
	// sha (taken as gitCommit).
	SubjectSpec string

	// SubjectArg is the optional second positional argument, the same
	// commit given without a flag. At most one of the two may be set.
	SubjectArg string

	// Subject is the parsed expected commit. Populated by Validate; nil
	// when none was given, which leaves the attestation unbound.
	Subject *subject.Expected

	// AttestationPath is the positional argument: path to the attestation
	// file (plain in-toto statement, DSSE envelope, or Sigstore bundle).
	AttestationPath string

	// Level is the raw --level flag: the SLSA source level the
	// attestation is required to reach, as a bare number or a
	// SLSA_SOURCE_LEVEL_N string. Parsed into MinLevel by Validate.
	Level string

	// MinLevel is the parsed required level. Controls above it are
	// informative: they cap the computed level without failing the run.
	MinLevel int

	// Spec is the SLSA spec version whose criteria the attestation is
	// verified against; empty means the latest the catalog defines.
	Spec string

	// ExpectedRepo, ExpectedBranch and ExpectedTag state the expected
	// origin of the revision (spec step 2). They feed the
	// expected_source_repo, expected_branch and expected_tag control
	// params; when unset those checks are skipped.
	ExpectedRepo   string
	ExpectedBranch string
	ExpectedTag    string

	// Since requires every control to have been active since at or
	// before the given date (RFC3339 or YYYY-MM-DD). It feeds the
	// enforced_since control param.
	Since string

	// Official toggles verification against the official SLSA source
	// workflow signing identity. Implies --require-signatures.
	Official bool

	// Verbose toggles inclusion of skipped controls and control titles in
	// the verify summary roster.
	Verbose bool
}

// AddFlags registers the source-specific flags on cmd.
func (o *sourceOptions) AddFlags(cmd *cobra.Command) {
	o.signingOptions.AddFlags(cmd)
	o.controlsOptions.AddFlags(cmd)
	o.vsaOutputOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVar(
		&o.Level, "level", "1",
		"required SLSA source level, 1-4 (eg 3 or SLSA_SOURCE_LEVEL_3)",
	)
	cmd.PersistentFlags().StringVar(
		&o.Spec, "spec", "",
		"SLSA spec version to verify against (eg 1.2) defaults to the latest",
	)
	cmd.PersistentFlags().StringVar(
		&o.ExpectedRepo, "expected-repo", "",
		"expected repository URI, eg https://github.com/example/repo",
	)
	cmd.PersistentFlags().StringVar(
		&o.ExpectedBranch, "expected-branch", "",
		"expected branch ref, eg refs/heads/main",
	)
	cmd.PersistentFlags().StringVar(
		&o.ExpectedTag, "expected-tag", "",
		"expected tag name (tag provenance only), eg v1.2.3",
	)
	cmd.PersistentFlags().StringVarP(
		&o.SubjectSpec, "subject", "s", "",
		"commit the attestation must be about (eg gitCommit:<sha>)",
	)
	cmd.PersistentFlags().StringVar(
		&o.Since, "since", "",
		"require controls active since at or before this date (RFC3339 or YYYY-MM-DD)",
	)
	cmd.PersistentFlags().BoolVar(
		&o.Official, "official", false,
		"require the attestation to be signed by the official SLSA Source identity",
	)
	cmd.PersistentFlags().BoolVarP(
		&o.Verbose, "verbose", "v", false,
		"show skipped controls and control titles in the summary",
	)
}

// Validate runs every option set's validator and propagates implications
// to the shared options struct.
func (o *sourceOptions) Validate() error {
	errs := []error{
		o.shared.Validate(),
		o.signingOptions.Validate(),
		o.controlsOptions.Validate(),
		o.vsaOutputOptions.Validate(),
	}
	if err := checkAttestationPath(o.AttestationPath); err != nil {
		errs = append(errs, err)
	}
	level, err := parseSourceLevel(o.Level)
	if err != nil {
		errs = append(errs, err)
	}
	o.MinLevel = level
	o.Subject = nil
	switch {
	case o.SubjectSpec != "" && o.SubjectArg != "":
		errs = append(errs, errors.New("give the expected commit either with --subject or as the second argument, not both"))
	case o.SubjectSpec != "" || o.SubjectArg != "":
		value := o.SubjectSpec
		if value == "" {
			value = o.SubjectArg
		}
		expected, err := parseSourceSubject(value)
		if err != nil {
			errs = append(errs, err)
		}
		o.Subject = expected
	}
	// The expectation flags feed the control params the source catalog
	// reads. They take precedence over an equivalent --param entry.
	if o.ExpectedRepo != "" {
		o.shared.Params["expected_source_repo"] = o.ExpectedRepo
	}
	if o.ExpectedBranch != "" {
		o.shared.Params["expected_branch"] = o.ExpectedBranch
	}
	if o.ExpectedTag != "" {
		// Tag provenance stores the bare tag name, not the full ref.
		o.shared.Params["expected_tag"] = strings.TrimPrefix(o.ExpectedTag, "refs/tags/")
	}
	if o.Since != "" {
		since, sErr := parseSinceDate(o.Since)
		if sErr != nil {
			errs = append(errs, sErr)
		} else {
			o.shared.Params["enforced_since"] = since
		}
	}
	if o.Official {
		for _, spec := range officialSourceSigners {
			id, err := sapi.NewIdentityFromSpec(spec)
			if err != nil {
				errs = append(errs, fmt.Errorf("building official identity: %w", err))
				continue
			}
			o.Signers = append(o.Signers, id)
		}
	}
	// --signer and --official imply --require-signatures: matching an
	// identity on an unsigned statement is meaningless.
	if len(o.Signers) > 0 {
		o.shared.RequireSignatures = true
	}
	return errors.Join(errs...)
}

// parseSourceSubject parses the expected commit: algorithm:digest as
// accepted by subject.Parse, or a bare 40-character hex string taken as
// a gitCommit digest, since that is what source provenance is about.
func parseSourceSubject(value string) (*subject.Expected, error) {
	value = strings.TrimSpace(value)
	if !strings.Contains(value, ":") {
		if len(value) == 2*intoto.AlgorithmGitCommit.HexLength() {
			value = string(intoto.AlgorithmGitCommit) + ":" + value
		} else {
			return nil, fmt.Errorf("invalid subject %q: want algorithm:digest (eg gitCommit:<sha>) or a 40-character commit sha", value)
		}
	}
	return subject.Parse(value)
}

// subjects returns the expected subject list for the verifier: the one
// commit given, or nothing.
func (o *sourceOptions) subjects() []*subject.Expected {
	if o.Subject == nil {
		return nil
	}
	return []*subject.Expected{o.Subject}
}

// parseSinceDate parses the --since flag value — an RFC3339 timestamp
// or a bare YYYY-MM-DD date — and normalises it to RFC3339 (a bare date
// means midnight UTC) so the CEL timestamp() conversion in the control
// expressions always succeeds.
func parseSinceDate(value string) (string, error) {
	value = strings.TrimSpace(value)
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t.UTC().Format(time.RFC3339), nil
	}
	if t, err := time.Parse(time.DateOnly, value); err == nil {
		return t.UTC().Format(time.RFC3339), nil
	}
	return "", fmt.Errorf("invalid --since date %q (want RFC3339 or YYYY-MM-DD)", value)
}

// parseSourceLevel parses the --level flag value: a bare number (1-4)
// or a SLSA_SOURCE_LEVEL_N label. There is no SLSA source level 0, and
// the library treats a zero minimum as "every applicable control must
// pass" — the strictest mode, the opposite of what a "level 0" reads
// as — so 0 is rejected rather than silently mapped to it.
func parseSourceLevel(value string) (int, error) {
	trimmed := strings.TrimPrefix(
		strings.ToUpper(strings.TrimSpace(value)), "SLSA_SOURCE_LEVEL_",
	)
	level, err := strconv.Atoi(trimmed)
	if err != nil || level < minSourceLevel || level > maxSourceLevel {
		return 0, fmt.Errorf("invalid source level %q (want %d-%d or SLSA_SOURCE_LEVEL_N)", value, minSourceLevel, maxSourceLevel)
	}
	return level, nil
}

const (
	minSourceLevel = 1
	maxSourceLevel = 4
)

// addSource registers the source subcommand on parentCmd.
func addSource(parentCmd *cobra.Command, shared *sharedOptions) {
	opts := &sourceOptions{shared: shared}
	sourceCmd := &cobra.Command{
		Short: "Verify a SLSA source attestation",
		Long: `Verify a SLSA source attestation against the SLSA spec-defined
source-track controls and any user-supplied controls.

The commit the attestation must be about can be given with --subject or
as a second argument, as algorithm:digest (eg gitCommit:<sha>) or a bare
40-character commit sha; the attestation's subject must match it or the
verification fails. Without it the attestation is verified on its
content alone.

The attestation may be supplied as a plain in-toto statement, a DSSE
envelope (signed with one or more keys via --key), or a Sigstore
bundle. Passing --official requires the attestation to be signed by
the official SLSA source workflow, at any of the repositories that have
hosted it.

The verification passes when the attestation reaches the level given
with --level (default 1), controls above it still run and determine
the SLSA source level reported (and emitted with --vsa), but do not
fail the verification.

State your expectations about the origin with --expected-repo and
--expected-branch. --since additionally requires every control to have
been active since at or before that date.

Signer identities (--signer) are spec strings of the form
sigstore::<issuer>::<identity>, matched exactly, or
sigstore(identityMatch=regex)::<issuer>::<identity-regexp>:

  sigstore::https://accounts.google.com::user@example.com
  sigstore(identityMatch=regex)::https://token.actions.githubusercontent.com::.*@example/.*`,
		Use: "source <attestation-path> [commit-digest]",
		Example: fmt.Sprintf(
			`%s source --level 3 --official --expected-branch refs/heads/main source-provenance.json`,
			appname,
		),
		SilenceUsage:  false,
		SilenceErrors: true,
		Args:          cobra.RangeArgs(1, 2),
		PreRunE: func(_ *cobra.Command, args []string) error {
			opts.AttestationPath = args[0]
			if len(args) > 1 {
				opts.SubjectArg = args[1]
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}
			cmd.SilenceUsage = true
			return runSource(cmd, opts)
		},
	}
	opts.AddFlags(sourceCmd)
	parentCmd.AddCommand(sourceCmd)
}

func runSource(cmd *cobra.Command, opts *sourceOptions) error {
	keys, err := opts.shared.ParseKeys()
	if err != nil {
		return fmt.Errorf("parsing keys: %w", err)
	}

	// The file may hold several attestations, as a commit's git note
	// does (source provenance, tag provenance, VSAs): pick the source
	// provenance about the commit — the tag provenance when a tag is
	// expected — over anything else.
	prefer := append(append([]string{}, sourceProvenanceTypes...), tagProvenanceTypes...)
	if opts.ExpectedTag != "" {
		prefer = append(append([]string{}, tagProvenanceTypes...), sourceProvenanceTypes...)
	}
	env, err := loadEnvelope(cmd.Context(), opts.AttestationPath, &attestation.Selection{
		Kind:               "source attestation",
		PredicateTypes:     prefer,
		Subjects:           opts.subjects(),
		NoGitDigestAliases: !opts.shared.GitDigestAliases,
		Prefer:             prefer,
	})
	if err != nil {
		return err
	}

	// Verify envelope signatures. Bare envelopes are unsigned and Verify
	// is a no-op for them. DSSE uses keys, Sigstore bundles verify
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

	v, err := slsa.New()
	if err != nil {
		return fmt.Errorf("building verifier: %w", err)
	}

	result, err := v.Verify(
		cmd.Context(),
		stmt,
		slsa.WithSubjects(opts.subjects()),
		slsa.WithGitDigestAliases(opts.shared.GitDigestAliases),
		slsa.WithParams(opts.shared.Params),
		slsa.WithRequireSignatures(opts.shared.RequireSignatures),
		slsa.WithExpectedSigners(opts.Signers),
		slsa.WithUserControlList(opts.Controls),
		slsa.WithTrack(controls.TrackSource),
		slsa.WithSpecVersion(opts.Spec),
		slsa.WithMinLevel(opts.MinLevel),
		slsa.WithVerifierID(opts.VerifierID),
		// There is no buildType concept on the source track: skip the
		// layer so it is not evaluated (or rendered) at all.
		slsa.WithBuildTypeControls(false),
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
	if err != nil {
		return fmt.Errorf("running verification: %w", err)
	}

	// With --vsa, stdout carries the unsigned VSA JSON instead of the
	// human-readable roster so it can be piped or stored directly.
	if opts.EmitVSA {
		if err := emitVSA(cmd.OutOrStdout(), stmt, result, controls.TrackSource); err != nil {
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
