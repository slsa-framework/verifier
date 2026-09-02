# SLSA Verifier

A command-line verifier for [SLSA](https://slsa.dev) attestations: build
provenance (`build`), source provenance (`source`) and Verification Summary
Attestations (`vsa`). It parses plain in-toto statements, DSSE envelopes and
Sigstore bundles, verifies their signatures when asked to, evaluates the
SLSA controls for the requested track and level, and can emit a VSA from the
result.

```bash
# Verify build provenance
slsa-verifier build  --require-signatures --signer <spec> --level 3 provenance.sigstore.json

# Verify source provenance
slsa-verifier source --official --level 3 --expected-branch refs/heads/main source-provenance.sigstore.json

# Verify a VSA
slsa-verifier vsa --verifier 'https://verify.example.com=<signer spec>' --level SLSA_BUILD_LEVEL_3 vsa.sigstore.json
```

Every subcommand prints `PASS` or `FAIL` with the per-control roster and
exits with `0` on pass, `1` on a verification failure and `2` when the
verification could not run (bad flags, unreadable input, missing key
material). Run any subcommand with `--help` for its flags and examples.

## Trust model

Read this before relying on the tool's output. The defaults are
deliberately permissive so that attestations can be inspected without any
key material, making a result *trustworthy* requires opting in.

- **Signatures are not required by default, but a refuted one always
  fails.** Without `--require-signatures`, an unsigned statement, or a
  signed one whose signature could not be checked, is evaluated on its
  content alone (and the result says so). A signature that was checked
  and did not verify fails the run regardless: unsigned means no claim
  of integrity, refuted means a claim of integrity that is false. With
  it, the statement must carry a signature that verified: a missing one
  fails the run, and a signed statement with nothing to verify it against
  (no `--key` for a key-signed DSSE envelope) is refused rather than
  passed. Legacy keyless envelopes (DSSE signed with a Sigstore
  certificate) are verified against the Rekor transparency log by default (`--rekor-url` names the instance) with no network they stay uncheckable and the run degrades as above.
- **Who signed is not checked unless you say who you expect.** A verified
  signature proves the content is intact, not that the right party produced
  it. Use `--signer <spec>` (all subcommands), `--official` (`source`, the
  official SLSA source workflow identity) or a per-verifier binding
  `--verifier <id>=<spec>` (`vsa`) to require a specific identity. Any of
  these implies `--require-signatures`.
- **Claims inside an attestation are claims.** `builder.id`, `verifier.id`
  and the controls a source provenance lists are written by whoever
  produced the document. Claims only mean something once the signer is bound
  to them: for `vsa` the tool refuses a verifier bound to no signer with
  `--verifier <id>=<spec>`, a registry file passed with `--verifiers`, or
  a wildcard `--signer` (unless you pass `--allow-unbound-verifier`). For
  `build`, a signed attestation's `builder.id` is bound to its signer
  through the builder registry and a builder nothing binds is reported
  unproven. For `source`, pass a signer.
- **The VSA it emits summarizes what it checked.** A VSA emitted with
  `--vsa` from an unsigned or unbound input is a summary of an unverified
  document. Only issue VSAs from runs that required and bound signatures.

See [SECURITY.md](SECURITY.md) for how to report a problem.

## Builder registry

A signed build attestation's `builder.id` is proven, not just checked,
by binding it to the identity that signed the statement.

The verifier ships a registry of builders and their signers and reports
the binding as the `builder-identity-bound` control. Builders of your
own can be bound with `--builder <id>=<signer spec>`, with a registry
file passed with `--builders`, or by naming the signer you expect with
`--signer`.

A signed attestation naming a builder nothing binds still verifies,
with `builder.id` reported unproven.

[docs/builder-registry.md](docs/builder-registry.md) describes the rules,
the file format and the embedded entries. VSA verifiers are bound the same
way with `--verifier <id>=<spec>` or a registry file passed with
`--verifiers` (see [docs/verifier-registry.md](docs/verifier-registry.md).)

Currently, the registry ships with the slsa-github-generator builders and
the GitHub Actions checks.

## Development

```bash
go build ./...
go test -race ./...
golangci-lint run ./...
```

(Test fixtures live under `pkg/slsa/testdata` see its README.)
