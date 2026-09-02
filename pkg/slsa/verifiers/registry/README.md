# Embedded verifier registry

YAML files in this directory are compiled into the verifier as its
default registry of VSA issuers bound to their signing identity. It
holds the official SLSA source workflow, which issues the VSAs the SLSA
source tool stores in git notes, under its current id and the ids of
the repositories that hosted it before. Other verifiers are bound with
`--verifier <id>=<signer spec>` or a registry file passed with
`--verifiers`, merged over these entries. The file format and the
binding rules are documented in
[docs/verifier-registry.md](../../../../docs/verifier-registry.md).
