// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
	sapi "github.com/policylabs/signer/api/v1"
	"github.com/spf13/cobra"

	"github.com/slsa-framework/verifier/pkg/attestation"
	"github.com/slsa-framework/verifier/pkg/slsa/verifiers"
)

// vsaOptions composes the flags specific to the vsa subcommand. The
// shared flags (--key, --param, --require-signatures) come from
// sharedOptions registered on the root command. --signer comes from
// the embedded signingOptions, as on build, and acts as a wildcard
// signer for every accepted verifier.
type vsaOptions struct {
	shared *sharedOptions
	signingOptions
	subjectOptions

	// VerifierSpecs holds the raw --verifier values, "id" or "id=spec".
	VerifierSpecs []string

	// Verifiers is the parsed, merged binding list. Populated by Validate.
	Verifiers []attestation.VerifierBinding

	// AllowUnbound accepts verifiers that have no authorized signer.
	AllowUnbound bool

	// RegistryPath is a verifier registry file or directory
	// (--verifiers) merged over the embedded registry.
	RegistryPath string

	// Registry is the merged verifier registry. Populated by Validate.
	Registry *verifiers.Registry

	Levels       []string
	Resource     string
	Policy       string
	Dependencies []string

	// AttestationPath is the first positional argument: path to the VSA
	// envelope file (plain in-toto statement, DSSE, or Sigstore bundle).
	// Any further positional arguments are artifact files the VSA must
	// be about (see subjectOptions).
	AttestationPath string
}

func (o *vsaOptions) AddFlags(cmd *cobra.Command) {
	o.signingOptions.AddFlags(cmd)
	o.subjectOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringArrayVar(
		&o.VerifierSpecs, "verifier", nil,
		"accepted verifier.id (optionally bound to a signer as id=<signer spec>)",
	)
	cmd.PersistentFlags().BoolVar(
		&o.AllowUnbound, "allow-unbound-verifier", false,
		"accept a --verifier that has no authorized signer (match its id only)",
	)
	cmd.PersistentFlags().StringVar(
		&o.RegistryPath, "verifiers", "",
		"YAML file or directory binding verifier ids to their signers",
	)
	cmd.PersistentFlags().StringArrayVar(
		&o.Levels, "level", nil,
		"required at-or-aobove SLSA level (eg SLSA_BUILD_LEVEL_3)",
	)
	cmd.PersistentFlags().StringVar(
		&o.Resource, "resource", "",
		"expected resourceUri (exact match, skipped if empty)",
	)
	cmd.PersistentFlags().StringVar(
		&o.Policy, "policy", "",
		"expected policy.uri (exact match, skipped if empty)",
	)
	cmd.PersistentFlags().StringArrayVar(
		&o.Dependencies, "dependency", nil,
		"expected dependencyLevels key (repeatable, every entry must appear)",
	)
}

// parseVerifierBindings turns the raw --verifier values into bindings.
// A value is "id" or "id=<signer spec>", split on the first "=": ids
// are URIs and the signer spec grammar puts its own "=" signs after
// "::", so the first "=" always separates the two. Repeated ids merge
// their signers.
func parseVerifierBindings(specs []string) ([]attestation.VerifierBinding, error) {
	var (
		bindings []attestation.VerifierBinding
		index    = map[string]int{}
		errs     []error
	)
	for _, raw := range specs {
		id, signerSpec, bound := strings.Cut(raw, "=")
		if id == "" {
			errs = append(errs, fmt.Errorf("--verifier %q: empty verifier id", raw))
			continue
		}
		pos, seen := index[id]
		if !seen {
			pos = len(bindings)
			index[id] = pos
			bindings = append(bindings, attestation.VerifierBinding{ID: id})
		}
		if !bound {
			continue
		}
		signer, err := sapi.NewIdentityFromSpec(signerSpec)
		if err != nil {
			errs = append(errs, fmt.Errorf("--verifier %q: parsing signer spec: %w", raw, err))
			continue
		}
		bindings[pos].Signers = append(bindings[pos].Signers, signer)
	}
	return bindings, errors.Join(errs...)
}

func (o *vsaOptions) Validate() error {
	errs := []error{o.shared.Validate(), o.signingOptions.Validate(), o.subjectOptions.Validate()}

	bindings, err := parseVerifierBindings(o.VerifierSpecs)
	if err != nil {
		errs = append(errs, err)
	}
	o.Verifiers = bindings
	if len(o.Verifiers) == 0 {
		errs = append(errs, errors.New("--verifier is required"))
	}

	registry, err := verifiers.LoadEmbedded()
	if err != nil {
		errs = append(errs, fmt.Errorf("loading the embedded verifier registry: %w", err))
		registry = &verifiers.Registry{}
	}
	if o.RegistryPath != "" {
		custom, err := verifiers.Load(o.RegistryPath)
		if err != nil {
			errs = append(errs, fmt.Errorf("--verifiers: %w", err))
		} else if err := registry.Merge(custom); err != nil {
			errs = append(errs, fmt.Errorf("--verifiers: %w", err))
		}
	}
	o.Registry = registry

	// A verifier.id is a claim written into the document. Only a signer
	// bound to it makes the match mean anything. Refuse unbound
	// verifiers unless the user says so explicitly.
	if !o.AllowUnbound && len(o.Signers) == 0 {
		for _, b := range o.Verifiers {
			if len(b.Signers) == 0 && registry.Lookup(b.ID) == nil {
				errs = append(errs, fmt.Errorf(
					"verifier %q has no authorized signer: bind one with --verifier %s=<signer spec> or a "+
						"registry file passed with --verifiers, add a wildcard --signer, or pass --allow-unbound-verifier", b.ID, b.ID))
			}
		}
	}

	// Binding a signer implies signatures are required: matching an
	// identity on an unsigned statement is meaningless.
	if len(o.Signers) > 0 {
		o.shared.RequireSignatures = true
	}
	for _, b := range o.Verifiers {
		if len(b.Signers) > 0 || registry.Lookup(b.ID) != nil {
			o.shared.RequireSignatures = true
		}
	}

	if err := checkAttestationPath(o.AttestationPath); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// toLibOptions converts the CLI flag struct to the library's
// VSAOptions. Kept as a tiny adapter so the CLI flag layer can evolve
// independently of the library's public option fields.
func (o *vsaOptions) toLibOptions() *attestation.VSAOptions {
	return &attestation.VSAOptions{
		Verifiers:    o.Verifiers,
		Signers:      o.Signers,
		AllowUnbound: o.AllowUnbound,
		Registry:     o.Registry,
		Levels:       o.Levels,
		Resource:     o.Resource,
		Policy:       o.Policy,
		Dependencies: o.Dependencies,
	}
}

// addVSA registers the vsa subcommand on parentCmd.
func addVSA(parentCmd *cobra.Command, shared *sharedOptions) {
	opts := &vsaOptions{shared: shared}
	vsaCmd := &cobra.Command{
		Short: "Verify a SLSA Verification Summary Attestation (VSA)",
		Long: `Verify a SLSA Verification Summary Attestation (VSA, v0.2 or v1).

After a VSA's envelope signature is verified (vis sigstore or passing
--key, yhe predicate is then converted to a version-neutral representation
and the following checks run:

  * verificationResult must be "PASSED" (always enforced)
  * verifier.id must be one of --verifier (always enforced). A verifier
    given without a signer takes the one a registry file passed with
    --verifiers binds to its id
  * the envelope's verified signer must be authorized for that verifier:
    bound to it with --verifier <id>=<signer spec>, or a wildcard --signer
    (enforced unless --allow-unbound-verifier is given)
  * verifiedLevels must satisfy one of --level (at-or-above per track
    eg: --level SLSA_BUILD_LEVEL_3 is satisfied by SLSA_BUILD_LEVEL_3 or
	SLSA_BUILD_LEVEL_4)
  * resourceUri must equal --resource (if set)
  * policy.uri must equal --policy (if set)
  * dependencyLevels must contain every --dependency key (if any given)

Artifact files given after the attestation are hashed with the digest
algorithms the VSA's subjects use, and --subject states a digest
directly. The VSA must be about every one of them or the verification
fails. Without any, the VSA is verified on its content alone.`,
		Use: "vsa <attestation-path> [artifact...]",
		Example: fmt.Sprintf(`  # Accept VSAs from one verifier, bound to the Sigstore identity that issues them
  %[1]s vsa --level SLSA_BUILD_LEVEL_3 \
    --verifier 'https://verify.example.com=sigstore::https://token.actions.githubusercontent.com::https://github.com/org/verifier/.github/workflows/verify.yaml@refs/heads/main' \
    vsa.sigstore.json

  # Two verifiers, each bound to its own signing key (DSSE envelopes need --key)
  %[1]s vsa --level SLSA_BUILD_LEVEL_3 \
    --verifier 'https://a.example.com=key::ecdsa-sha2-nistp256::7c1a0f2b9e3d4c55' --key a.pem \
    --verifier 'https://b.example.com=key::ecdsa-sha2-nistp256::2f9e8d7c6b5a4433' --key b.pem \
    vsa.dsse.json

  # A wildcard --signer may sign for any accepted verifier
  %[1]s vsa --verifier https://a.example.com --verifier https://b.example.com \
    --signer 'sigstore(identityMatch=regex)::https://accounts.google.com::.*@example\.com' \
    vsa.sigstore.json

  # Match the verifier id only, trusting nothing about who signed (not recommended)
  %[1]s vsa --verifier https://verify.example.com --allow-unbound-verifier vsa.intoto.json`,
			appname,
		),
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
			return runVSA(cmd, opts)
		},
	}
	opts.AddFlags(vsaCmd)
	parentCmd.AddCommand(vsaCmd)
}

func runVSA(cmd *cobra.Command, opts *vsaOptions) error {
	keys, err := opts.shared.ParseKeys()
	if err != nil {
		return fmt.Errorf("parsing keys: %w", err)
	}

	v := attestation.New()
	// The file may hold several attestations: pick the VSA, about the
	// stated subjects when any were given.
	env, err := loadEnvelope(cmd.Context(), opts.AttestationPath, &attestation.Selection{
		Kind:               "VSA",
		PredicateTypes:     vsaPredicateTypes,
		Subjects:           opts.Subjects,
		NoGitDigestAliases: !opts.shared.GitDigestAliases,
	})
	if err != nil {
		return err
	}
	if err := v.VerifySignatures(env, attestation.SignatureOptions{
		Keys:              keys,
		RekorVerification: true,
		RekorURL:          opts.shared.RekorURL,
		Required:          opts.shared.RequireSignatures,
	}); err != nil {
		switch {
		case errors.Is(err, attestation.ErrSignatureRequired), errors.Is(err, attestation.ErrSignatureUnverified):
			// A verification outcome: unsigned, or checked and refuted.
			writef(cmd.OutOrStdout(), "%s\n  Signature: %s\n", redf("FAIL"), err)
			return ErrVerifyFailed
		case errors.Is(err, attestation.ErrSignatureUnverifiable):
			// Not an outcome: the signature could not be checked at all.
			// Surface it as an execution error so the missing material
			// is not mistaken for a bad signature.
			return fmt.Errorf("%w (DSSE envelopes need the signer's public key, pass it with --key)", err)
		}
		return err
	}

	expected, err := opts.resolve(env.GetStatement())
	if err != nil {
		return err
	}
	libOpts := opts.toLibOptions()
	libOpts.Subjects = expected
	libOpts.NoGitDigestAliases = !opts.shared.GitDigestAliases
	result, err := v.VerifyVSA(cmd.Context(), env, libOpts)
	if err != nil {
		return err
	}
	printVSAResult(cmd.OutOrStdout(), result)
	if !result.Pass() {
		return ErrVerifyFailed
	}
	return nil
}

// formatDependencyLevels renders a dependencyLevels map as
// "LEVEL=count, …" with keys in sorted order so the output is stable
// across runs.
func formatDependencyLevels(m map[string]uint64) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

// printVSAResult writes the PASS/FAIL header, a summary of the VSA's
// key fields, and the table of check outcomes. Format mirrors the
// build subcommand's printer so user-facing output stays consistent.
func printVSAResult(w io.Writer, result *attestation.VSAResult) {
	v := result.VSA
	if result.Pass() {
		writef(w, "%s\n", greenf("PASS"))
	} else {
		writef(w, "%s\n", redf("FAIL"))
	}
	writef(w, "VSA: %s\n", v.PredicateType)
	writef(w, "\n")

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if len(result.Signers) > 0 {
		writef(tw, "  Verifier:\t%s (signed by %s)\n", v.Verifier.ID, strings.Join(result.Signers, ", "))
	} else {
		writef(tw, "  Verifier:\t%s\n", v.Verifier.ID)
	}
	writef(tw, "  Result:\t%s\n", v.VerificationResult)
	if v.ResourceURI != "" {
		writef(tw, "  Resource:\t%s\n", v.ResourceURI)
	}
	if v.Policy.URI != "" {
		writef(tw, "  Policy:\t%s\n", v.Policy.URI)
	}
	if len(v.VerifiedLevels) > 0 {
		writef(tw, "  Levels:\t%s\n", strings.Join(v.VerifiedLevels, ", "))
	}
	if len(v.DependencyLevels) > 0 {
		writef(tw, "  Dependencies:\t%s\n", formatDependencyLevels(v.DependencyLevels))
	}
	flushTabWriter(tw)
	writef(w, "\n")

	printSubjects(w, result.Subjects)

	writef(w, "Checks:\n")
	ct := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, c := range result.Checks {
		line := fmt.Sprintf("  %s\t%s", vsaCheckMarker(c.Pass), c.Name)
		if !c.Pass && c.Message != "" {
			line += "\t" + dimf(c.Message)
		}
		writef(ct, "%s\n", line)
	}
	flushTabWriter(ct)
}

// vsaCheckMarker mirrors statusMarker but for the boolean pass/fail
// shape used by VSA checks.
func vsaCheckMarker(pass bool) string {
	if color.NoColor {
		if pass {
			return "[PASS]"
		}
		return "[FAIL]"
	}
	if pass {
		return color.GreenString("✓")
	}
	return color.RedString("✗")
}
