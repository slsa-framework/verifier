// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"context"
	"fmt"
	"os"
	"strings"

	cdattestation "github.com/policylabs/attestation"
	"github.com/policylabs/collector/envelope"
	"github.com/policylabs/collector/repository/filesystem"
	"github.com/policylabs/collector/repository/jsonl"
)

// Fetch loads the attestations at path, in order: every attestation
// file under a directory, one attestation per line of a JSON lines
// file (.jsonl, as a commit's git note or a release's attestations
// file are written), or the single bundle, DSSE envelope or bare
// statement any other file holds. The collector's drivers do the
// reading: the JSON lines one is not reached by its format detection,
// so it is chosen here by extension.
func (*Verifier) Fetch(ctx context.Context, path string) ([]Envelope, error) {
	envs, err := fetch(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("loading attestations from %s: %w", path, err)
	}
	if len(envs) == 0 {
		return nil, fmt.Errorf("no attestation found at %s", path)
	}
	return envs, nil
}

func fetch(ctx context.Context, path string) ([]Envelope, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	var repo cdattestation.Repository
	switch {
	case info.IsDir():
		repo, err = filesystem.Build(path)
	case strings.HasSuffix(path, ".jsonl"):
		repo, err = jsonl.Build(path)
	default:
		return envelope.Parsers.ParseFiles([]string{path})
	}
	if err != nil {
		return nil, err
	}
	fetcher, ok := repo.(cdattestation.Fetcher)
	if !ok {
		return nil, fmt.Errorf("the collector for %s cannot read attestations", path)
	}
	return fetcher.Fetch(ctx, cdattestation.FetchOptions{})
}

// Load parses a single attestation envelope from path. Format
// auto-detection covers bare in-toto statements, DSSE envelopes,
// and Sigstore bundles; the returned Envelope already has its
// predicate parsed by the SLSA / VSA parser registry the package
// wires up via init().
//
// Returns an error if the file produces zero envelopes or more than
// one; see Fetch and Select for files holding several.
func (v *Verifier) Load(path string) (Envelope, error) {
	envs, err := v.Fetch(context.Background(), path)
	if err != nil {
		return nil, err
	}
	if len(envs) > 1 {
		return nil, fmt.Errorf("expected one attestation, got %d", len(envs))
	}
	return envs[0], nil
}
