// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package verifiers

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed registry
var registryFS embed.FS

const registryRoot = "registry"

// file is the YAML schema of a registry file: a verifiers list.
type file struct {
	Verifiers []*Verifier `yaml:"verifiers"`
}

// Parse reads a registry file's YAML.
func Parse(data []byte) (*Registry, error) {
	var f file
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	return New(f.Verifiers...)
}

// LoadEmbedded loads the verifiers compiled into the binary: the
// official SLSA source workflow under its current and legacy ids.
func LoadEmbedded() (*Registry, error) {
	return loadFS(registryFS, registryRoot)
}

// Load reads a registry from a YAML file or a directory of YAML files.
func Load(path string) (*Registry, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.IsDir() {
		return loadFS(os.DirFS(path), ".")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	r, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return r, nil
}

// loadFS merges every YAML file under root, in path order so overrides
// are predictable.
func loadFS(fsys fs.FS, root string) (*Registry, error) {
	var files []string
	walkErr := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")) {
			files = append(files, p)
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	sort.Strings(files)

	r := &Registry{}
	for _, p := range files {
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", p, err)
		}
		part, err := Parse(data)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", p, err)
		}
		if err := r.Merge(part); err != nil {
			return nil, fmt.Errorf("merging %s: %w", p, err)
		}
	}
	return r, nil
}
