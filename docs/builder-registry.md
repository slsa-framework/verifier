# The builder registry

A build provenance says who built the artifact in `builder.id`. That
field is written by whoever produced the document, so on its own it is a
claim: anyone able to sign a statement can name any builder in it. The
verifier's `builder-id-trusted` control checks the claim against the
`trusted_builders` allowlist; the **builder registry** is what turns the
claim into a proof, by saying which signing identity each builder uses so
the verified signature can be tied to the builder named.

This is the same idea the original `slsa-framework/slsa-verifier` applied
to the slsa-github-generator: it accepted provenance only when the Fulcio
certificate that signed it named one of the generator's reusable
workflows, at a release tag. The registry expresses that as data and
extends it to builders of your own.

## How the binding works

For every signed build attestation, after the core controls run, the
verifier binds `builder.id` to the identities that signed the statement
and reports the outcome as one more core control,
`builder-identity-bound`, at SLSA Build **L2** — the level that requires
provenance to be signed by the build platform.

1. The registry is searched for the builder `builder.id` names (with any
   `@ref` suffix removed) and for each verified signer.
2. A signer that a registry entry recognises proves the entry's builder.
   For an ordinary entry, the builder named in `builder.id` must be that
   builder, at the same ref the signer ran at. For a **delegated** entry
   (a builder that runs other builders), `builder.id` names the delegated
   builder and is not compared with the signer at all. For an **observer**
   entry (a watcher that attests runs it observed), `builder.id` must name
   the workflow the signing certificate's build config extension records —
   the workflow whose run the observer attested — which proves that
   workflow really ran.
3. The signer's ref must satisfy the entry's **ref policy**, so a builder
   running from a branch is not mistaken for the released builder its id
   names.
4. When the entry is **source-repository bound** and `expected_source`
   was given, the signing certificate's source repository extension must
   name the expected repository: the workflow that requested the
   certificate ran where the artifact's source lives.

| Situation | `builder-identity-bound` |
|---|---|
| The statement carries no verified signature | `SKIP` — builder.id stays a claim; `--require-signatures` decides whether that is acceptable |
| A verified signer is the builder's signer, at an allowed ref, same release, right source repository | `PASS` |
| A verified signer is a delegated builder's signer | `PASS` — the delegated builder's trust is `trusted_builders`' decision |
| A verified signer is an observer whose certificate names the workflow `builder.id` claims | `PASS` — the certificate proves that workflow's run was observed |
| An observer's certificate names another workflow, another ref, or no workflow at all | `FAIL` |
| The builder is known but the signer is someone else | `FAIL` |
| The builder's own signer, at another ref or a ref the policy rejects | `FAIL` |
| A known builder's signer signed provenance naming a different builder | `FAIL` |
| The certificate was issued to another source repository | `FAIL` |
| Neither the builder nor any signer is known, but a signer is one named with `--signer` | `PASS` — naming the signer you expect binds whatever builder it signs for |
| Neither the builder nor any signer is known to the registry | `SKIP` — "builder.id is unproven", repeated in the result header so it is seen without `-v` |
| The predicate has no builder (source track) | no row |

A `FAIL` fails the run and caps the level below L2, like any core
control. With several verified signers, one that binds is enough;
otherwise the first failure is reported, and the builder is unproven
only when no signer is known at all.

An unproven builder does not fail the run. The verifier's defaults are
permissive — signatures are not even required unless asked — and a
statement must not become harder to verify because its author started
signing it. What the tool cannot do is tell a legitimate unknown builder
from an impostor, so it says so in the result header:

```
PASS
SLSA Level: 3 (spec v1.0)
builder.id "https://ci.example.com/builder" is unproven: signed by spiffe://example.com/ci/builder, which no known builder uses
```

To turn that into a proof, bind the builder: register it (below), or
name the signer you expect with `--signer`, which binds any builder the
registry does not know to that signer — the same role `--signer` plays
for verifiers on the `vsa` command. Binding never overrides the registry:
a known builder must be signed by its own signer, whatever `--signer`
says.

## What the registry knows out of the box

The embedded registry (`pkg/slsa/builders/registry/github.yaml`)
describes builders running on GitHub Actions. Their provenance is signed
with a Fulcio certificate issued to the workflow that ran, so the
certificate subject names the workflow and its ref
(`https://github.com/org/repo/.github/workflows/build.yml@refs/tags/v1.2.3`)
and the certificate's source repository extension names the repository
whose workflow requested it.

| Builder | Ref policy | Kind | Source bound |
|---|---|---|---|
| `…/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml` | release tag | builder | yes |
| `…/slsa-github-generator/.github/workflows/builder_go_slsa3.yml` | release tag | builder | yes |
| `…/slsa-github-generator/.github/workflows/builder_container-based_slsa3.yml` | release tag | builder | yes |
| `…/slsa-github-generator/.github/workflows/delegator_generic_slsa3.yml` | release tag | **delegator** | yes |
| `…/slsa-github-generator/.github/workflows/delegator_lowperms-generic_slsa3.yml` | release tag | **delegator** | yes |
| `…/actions/.github/workflows/attest_actions.yml` | any | **observer** | yes |
| `https://github.com/` (prefix) | any | platform | yes |

The attester entry is the [SLSA build attester](https://github.com/slsa-framework/attester)'s
reusable workflow, an observer: it watches the calling workflow's run and
attests the artifacts it produced, and the binding proves `builder.id`
through the certificate's build config extension, which records the
calling workflow. Its ref policy is `any` until slsa-framework/actions
tags releases.

The last entry covers any GitHub Actions workflow signing its own
provenance, as GitHub's artifact attestations and build-your-own-builder
workflows do: `builder.id` is the workflow that ran and the certificate
names the same workflow. The binding proves the workflow named really
ran; whether to trust that workflow remains the caller's decision through
`trusted_builders`. Exact entries take precedence over prefix entries, so
the generator workflows are matched by their own rows, not by the
platform row.

## Registry files

A registry file is YAML with a `builders` list:

```yaml
builders:
  - id: https://ci.example.com/builder
    title: Example CI builder
    description: |
      Builds release artifacts from the example.com monorepo and signs
      provenance with its SPIFFE workload identity.
    signer: spiffe://example.com/ci/builder
    ref: any

  - id: https://gitlab.example.com/group/project//.gitlab-ci.yml
    title: GitLab CI pipeline
    issuer: https://gitlab.example.com
    ref: semver-tag
    sourceRepositoryBound: true
```

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | The builder id as provenance records it in `builder.id`, **without** the `@ref` the GitHub builders append. |
| `idMatch` | no | `exact` (default) or `prefix`. With `prefix`, any `builder.id` starting with `id` belongs to this entry, and the signer's own subject must be the workflow `builder.id` names. |
| `title`, `description` | no | For people; the title appears in messages. |
| `issuer` | one of `issuer`/`signer` | The OIDC issuer of the builder's signing certificate. The signer identity is derived from it and `id`: a sigstore identity from `issuer` whose subject starts with `id` (followed by `@` and the ref for exact entries). This fits workflow-style identities whose certificate subject *is* the builder id. |
| `signer` | one of `issuer`/`signer` | A full identity spec when the signer cannot be derived: `sigstore::<issuer>::<subject>`, `sigstore(identityMatch=prefix)::<issuer>::<subject-prefix>`, `key::<type>::<id>`, `spiffe://…`. Matchers: `exact`, `regex`, `prefix`, `glob`. |
| `ref` | no | `any` (default) or `semver-tag`: the ref after `@` in the signer's subject must be `refs/tags/vX.Y.Z` (a prerelease suffix is fine, build metadata and `v1.2` are not). |
| `delegated` | no | The entry is a delegator. Its certificate proves the delegator ran; `builder.id` names the delegated builder and is not compared with the signer. |
| `observer` | no | The entry is an observer: `id` names its own workflow (matched by signer, exact only), and `builder.id` must name the workflow the certificate's build config extension records — the workflow whose run it observed. Mutually exclusive with `delegated`. |
| `sourceRepositoryBound` | no | The signing certificate's source repository is the repository the artifact was built from, and is compared with `expected_source` when given. |

Entries are validated on load: an empty id, an id carrying a ref, an
unknown `idMatch` or `ref`, a missing `issuer`/`signer`, or an identity
spec that does not parse are errors. Within a registry, a later entry
with the same `id` and `idMatch` replaces the earlier one; a directory of
files is merged in path order.

## Using it from the command line

```
slsa-verifier build [flags] provenance.json
  --builder id=<signer spec>      bind one builder (repeatable)
  --builder id=<OIDC issuer>      same, deriving the signer as a registry entry would
  --builders <file|dir>           merge a registry file over the embedded one
  --signer <signer spec>          expect this signer; binds builders the registry does not know
```

Precedence is `--builder` over `--builders` over the embedded registry.
A `--builder` binding is exact on id, accepts any ref and does not bind
the source repository; write a registry file for anything more. The
value after `=` is taken as an identity spec when it has a spec's shape
(`…::…`, `spiffe://…`, `ref:…`) and as an issuer otherwise.

```
# Provenance from the slsa-github-generator: nothing to configure, the
# registry knows the generator and refuses provenance it did not sign.
slsa-verifier build --param expected_source:github.com/example/repo \
    --param trusted_builders:[https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0] \
    --param expected_tag:v1.2.3 provenance.intoto.jsonl app.tgz

# Your own builder, signed with a key: bind it to the key, either by
# expecting that signer or by registering it as the builder's.
slsa-verifier build --key ci.pem \
    --param expected_source:github.com/example/repo \
    --param trusted_builders:[https://ci.example.com/builder] \
    --signer key::ecdsa-sha2-nistp256::<key id> \
    --skip-buildtype-checks provenance.dsse.json
slsa-verifier build --key ci.pem \
    --param expected_source:github.com/example/repo \
    --param trusted_builders:[https://ci.example.com/builder] \
    --builder https://ci.example.com/builder=key::ecdsa-sha2-nistp256::<key id> \
    --skip-buildtype-checks provenance.dsse.json

# An organization registry checked into the repository.
slsa-verifier build --builders ci/builders.yaml ... provenance.sigstore.json
```

When a signed attestation names a builder nothing binds, the run still
verifies and the header says the builder is unproven; the
`builder-identity-bound` row is skipped and shown with `-v`.

## Using it from Go

```go
import (
    "github.com/slsa-framework/verifier/pkg/slsa"
    "github.com/slsa-framework/verifier/pkg/slsa/builders"
)

reg, err := builders.LoadEmbedded()          // or builders.Load("ci/builders.yaml")
b, err := builders.ParseBinding("https://ci.example.com/builder=spiffe://example.com/ci/builder")
err = reg.Add(b)                              // replaces an entry with the same id

v, err := slsa.New(slsa.WithBuilders(reg))
res, err := v.Verify(ctx, statement,
    slsa.WithExpectedSigner(id),              // binds builders the registry does not know
    // ...
)
```

The binding is the core result with `ID == slsa.BuilderBindingControlID`;
when it is skipped for an unproven builder, `Result.Message` repeats
its message. `Registry.Lookup(builderID)` and
`Registry.ForSigner(identity)` answer the two questions the binding
asks — which builder does this id name, and whose signer is this
identity — exact entries first.
