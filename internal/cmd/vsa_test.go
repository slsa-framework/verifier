// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/policylabs/signer/key"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A public key that did not sign the fixtures.
const wrongKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEq0F7Qy812rYgbwi5c1wSnevN8FEC
hDjayw2lL6wkyR9k1vWICQYbe4FqOZeulBbfWBU7/BKdtlwKRStEVEffvg==
-----END PUBLIC KEY-----`

// newVSAOptions builds a vsaOptions the way the command would after flag
// parsing, and validates it.
func newVSAOptions(t *testing.T, path string, mod func(o *vsaOptions)) (*vsaOptions, error) {
	t.Helper()
	opts := &vsaOptions{
		shared:          &sharedOptions{},
		Levels:          []string{"SLSA_BUILD_LEVEL_3"},
		AttestationPath: path,
	}
	if mod != nil {
		mod(opts)
	}
	return opts, opts.Validate()
}

func runVSAWith(t *testing.T, opts *vsaOptions) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	err := runVSA(cmd, opts)
	return out.String(), err
}

// testdata/forged-vsa.dsse.json is a PASSED VSA for verifier.id
// https://verify.example.com at SLSA_BUILD_LEVEL_4, wrapped in a DSSE
// envelope signed with a throwaway key nobody has: a well-formed
// signature that no supplied key will ever verify.
// testdata/garbage-sig-vsa.dsse.json is the same VSA with signature
// bytes that are not a signature at all.
func TestRunVSASignatureOutcomes(t *testing.T) {
	t.Parallel()

	keyPath := filepath.Join(t.TempDir(), "wrong.pem")
	require.NoError(t, os.WriteFile(keyPath, []byte(wrongKeyPEM), 0o600))

	for _, tc := range []struct {
		name       string
		fixture    string // defaults to forged-vsa.dsse.json
		required   bool
		keyPaths   []string
		wantErr    error  // sentinel the error must wrap; nil means success
		wantExec   bool   // true: an execution error (exit 2), not ErrVerifyFailed
		wantOutput string // substring expected on stdout
		wantMsg    string // substring expected in the error
	}{
		{
			name:       "not required: forged signature is ignored, VSA passes",
			wantOutput: "PASS",
		},
		{
			name:     "required, no key: unverifiable is an execution error",
			required: true, wantExec: true, wantMsg: "--key",
		},
		{
			name:     "required, wrong key: did not verify is a FAIL",
			required: true, keyPaths: []string{keyPath},
			wantErr: ErrVerifyFailed, wantOutput: "did not verify",
		},
		{
			// Bytes that are not a signature are a bad signature, not a
			// tooling problem: the key was supplied and the check ran.
			name:    "required, key supplied, garbage signature bytes: FAIL, not an error",
			fixture: "garbage-sig-vsa.dsse.json", required: true, keyPaths: []string{keyPath},
			wantErr: ErrVerifyFailed, wantOutput: "did not verify",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fixture := "forged-vsa.dsse.json"
			if tc.fixture != "" {
				fixture = tc.fixture
			}
			opts, err := newVSAOptions(t, filepath.Join("testdata", fixture), func(o *vsaOptions) {
				o.shared.RequireSignatures = tc.required
				o.shared.PublicKeyPaths = tc.keyPaths
				o.VerifierSpecs = []string{"https://verify.example.com"}
				o.AllowUnbound = true // these cases are about signatures, not binding
			})
			require.NoError(t, err)

			out, err := runVSAWith(t, opts)
			if tc.wantOutput != "" {
				assert.Contains(t, out, tc.wantOutput)
			}
			switch {
			case tc.wantExec:
				require.Error(t, err)
				require.NotErrorIs(t, err, ErrVerifyFailed, "must not be reported as a verification failure")
				assert.Contains(t, err.Error(), tc.wantMsg)
			case tc.wantErr != nil:
				require.ErrorIs(t, err, tc.wantErr)
			default:
				require.NoError(t, err)
			}
		})
	}
}

func TestParseVerifierBindings(t *testing.T) {
	t.Parallel()

	t.Run("ids, bindings and merging", func(t *testing.T) {
		t.Parallel()
		bindings, err := parseVerifierBindings([]string{
			"https://a.example.com",
			"https://b.example.com=key::rsa::1234abcdef",
			// The signer spec grammar carries its own "=": only the first one splits.
			"https://b.example.com=sigstore(issuerMatch=exact,identityMatch=regex)::https://accounts.google.com::.*@example\\.com",
			"https://c.example.com=spiffe://example.org/workload",
		})
		require.NoError(t, err)
		require.Len(t, bindings, 3)

		assert.Equal(t, "https://a.example.com", bindings[0].ID)
		assert.Empty(t, bindings[0].Signers)

		assert.Equal(t, "https://b.example.com", bindings[1].ID)
		require.Len(t, bindings[1].Signers, 2, "repeated ids merge their signers")
		assert.Equal(t, "1234abcdef", bindings[1].Signers[0].GetKey().GetId())
		// Annotated slots land in the matchers, not the legacy fields.
		sigstore := bindings[1].Signers[1].GetSigstore()
		assert.Equal(t, "https://accounts.google.com", sigstore.GetIssuerMatch().GetExact())
		assert.Equal(t, `.*@example\.com`, sigstore.GetIdentityMatch().GetRegex(), "matcher annotations survive the split")

		assert.Equal(t, "https://c.example.com", bindings[2].ID)
		require.Len(t, bindings[2].Signers, 1)
		assert.Equal(t, "spiffe://example.org/workload", bindings[2].Signers[0].GetSpiffe().GetSvid())
	})

	t.Run("errors", func(t *testing.T) {
		t.Parallel()
		_, err := parseVerifierBindings([]string{"=key::rsa::1234"})
		require.ErrorContains(t, err, "empty verifier id")
		_, err = parseVerifierBindings([]string{"https://a.example.com=not-a-spec"})
		require.ErrorContains(t, err, "parsing signer spec")
	})
}

func TestVSAOptionsValidateBinding(t *testing.T) {
	t.Parallel()
	fixture := filepath.Join("testdata", "forged-vsa.dsse.json")

	t.Run("unbound verifier is refused with a hint", func(t *testing.T) {
		t.Parallel()
		_, err := newVSAOptions(t, fixture, func(o *vsaOptions) {
			o.VerifierSpecs = []string{"https://a.example.com"}
		})
		require.ErrorContains(t, err, "https://a.example.com")
		require.ErrorContains(t, err, "--allow-unbound-verifier")
	})

	t.Run("one bound, one unbound: the unbound one is named", func(t *testing.T) {
		t.Parallel()
		_, err := newVSAOptions(t, fixture, func(o *vsaOptions) {
			o.VerifierSpecs = []string{"https://a.example.com=key::rsa::1", "https://b.example.com"}
		})
		require.ErrorContains(t, err, `"https://b.example.com"`)
		require.NotContains(t, err.Error(), `"https://a.example.com"`)
	})

	t.Run("bound verifier implies signatures", func(t *testing.T) {
		t.Parallel()
		opts, err := newVSAOptions(t, fixture, func(o *vsaOptions) {
			o.VerifierSpecs = []string{"https://a.example.com=key::rsa::1"}
		})
		require.NoError(t, err)
		assert.True(t, opts.shared.RequireSignatures)
	})

	t.Run("wildcard signer binds every verifier and implies signatures", func(t *testing.T) {
		t.Parallel()
		opts, err := newVSAOptions(t, fixture, func(o *vsaOptions) {
			o.VerifierSpecs = []string{"https://a.example.com", "https://b.example.com"}
			o.SignerSpecs = []string{"key::rsa::1"}
		})
		require.NoError(t, err)
		assert.True(t, opts.shared.RequireSignatures)
		lib := opts.toLibOptions()
		require.Len(t, lib.Signers, 1)
		require.Len(t, lib.Verifiers, 2)
	})

	t.Run("allow-unbound accepts and does not imply signatures", func(t *testing.T) {
		t.Parallel()
		opts, err := newVSAOptions(t, fixture, func(o *vsaOptions) {
			o.VerifierSpecs = []string{"https://a.example.com"}
			o.AllowUnbound = true
		})
		require.NoError(t, err)
		assert.False(t, opts.shared.RequireSignatures)
		assert.True(t, opts.toLibOptions().AllowUnbound)
	})
}

// signingKey is a generated ECDSA key with its public PEM on disk and the
// signer spec that names it.
type signingKey struct {
	priv    *ecdsa.PrivateKey
	pemPath string
	spec    string
}

func newSigningKey(t *testing.T, dir, name string) signingKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	pemPath := filepath.Join(dir, name+".pem")
	require.NoError(t, os.WriteFile(pemPath, pemData, 0o600))

	// Name the key the way the verifier records it: key::<scheme>::<id>.
	pub, err := key.NewParser().ParsePublicKey(pemData)
	require.NoError(t, err)
	return signingKey{priv: priv, pemPath: pemPath, spec: fmt.Sprintf("key::%s::%s", pub.Scheme, pub.ID())}
}

// signVSA writes a DSSE envelope wrapping a PASSED SLSA_BUILD_LEVEL_4 VSA
// that claims verifierID, signed by k.
func signVSA(t *testing.T, dir, name, verifierID string, k signingKey) string {
	t.Helper()
	return signVSAFor(t, dir, name, verifierID, k, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
}

// signVSAFor is signVSA with the VSA subject's sha256 digest chosen by
// the caller.
func signVSAFor(t *testing.T, dir, name, verifierID string, k signingKey, subjectSHA256 string) string {
	t.Helper()
	statement := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []map[string]any{{"name": "x", "digest": map[string]string{"sha256": subjectSHA256}}},
		"predicateType": "https://slsa.dev/verification_summary/v1",
		"predicate": map[string]any{
			"verifier": map[string]string{"id": verifierID}, "timeVerified": "2026-01-01T00:00:00Z",
			"resourceUri": "pkg:oci/foo@sha256:abc", "policy": map[string]string{"uri": "https://p"},
			"verificationResult": "PASSED", "verifiedLevels": []string{"SLSA_BUILD_LEVEL_4"},
		},
	}
	payload, err := json.Marshal(statement)
	require.NoError(t, err)
	return signDSSE(t, dir, name, payload, k)
}

// signDSSE writes a DSSE envelope wrapping the in-toto payload, signed
// by k, and returns its path.
func signDSSE(t *testing.T, dir, name string, payload []byte, k signingKey) string {
	t.Helper()
	const payloadType = "application/vnd.in-toto+json"
	pae := fmt.Appendf(nil, "DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload)
	digest := sha256.Sum256(pae)
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	require.NoError(t, err)

	env, err := json.Marshal(map[string]any{
		"payloadType": payloadType,
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"signatures":  []map[string]string{{"keyid": name, "sig": base64.StdEncoding.EncodeToString(sig)}},
	})
	require.NoError(t, err)
	path := filepath.Join(dir, name+".dsse.json")
	require.NoError(t, os.WriteFile(path, env, 0o600))
	return path
}

// The binding end to end: two verifiers, each with its own key.
func TestRunVSAVerifierBinding(t *testing.T) {
	t.Parallel()
	const verifierA, verifierB = "https://a.example.com", "https://b.example.com"
	dir := t.TempDir()
	keyA := newSigningKey(t, dir, "a")
	keyB := newSigningKey(t, dir, "b")
	aByA := signVSA(t, dir, "a-by-a", verifierA, keyA)
	bByA := signVSA(t, dir, "b-by-a", verifierB, keyA)
	bByB := signVSA(t, dir, "b-by-b", verifierB, keyB)
	bothKeys := []string{keyA.pemPath, keyB.pemPath}

	for _, tc := range []struct {
		name       string
		envelope   string
		mod        func(o *vsaOptions)
		wantPass   bool
		wantOutput string
	}{
		{
			name: "A signed by A's key", envelope: aByA,
			mod: func(o *vsaOptions) {
				o.VerifierSpecs = []string{verifierA + "=" + keyA.spec, verifierB + "=" + keyB.spec}
				o.shared.PublicKeyPaths = bothKeys
			},
			wantPass: true, wantOutput: "signed by " + keyA.spec,
		},
		{
			name: "B signed by B's key", envelope: bByB,
			mod: func(o *vsaOptions) {
				o.VerifierSpecs = []string{verifierA + "=" + keyA.spec, verifierB + "=" + keyB.spec}
				o.shared.PublicKeyPaths = bothKeys
			},
			wantPass: true, wantOutput: "signed by " + keyB.spec,
		},
		{
			// The case the binding exists for: A's key vouching as B.
			name: "B signed by A's key", envelope: bByA,
			mod: func(o *vsaOptions) {
				o.VerifierSpecs = []string{verifierA + "=" + keyA.spec, verifierB + "=" + keyB.spec}
				o.shared.PublicKeyPaths = bothKeys
			},
			wantPass: false, wantOutput: "not authorized for this verifier",
		},
		{
			name: "wildcard signer vouches for B", envelope: bByA,
			mod: func(o *vsaOptions) {
				o.VerifierSpecs = []string{verifierA, verifierB}
				o.SignerSpecs = []string{keyA.spec}
				o.shared.PublicKeyPaths = bothKeys
			},
			wantPass: true,
		},
		{
			name: "unbound, allowed: id match only, no key needed", envelope: bByA,
			mod: func(o *vsaOptions) {
				o.VerifierSpecs = []string{verifierB}
				o.AllowUnbound = true
			},
			wantPass: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts, err := newVSAOptions(t, tc.envelope, tc.mod)
			require.NoError(t, err)

			out, err := runVSAWith(t, opts)
			if tc.wantOutput != "" {
				assert.Contains(t, out, tc.wantOutput)
			}
			if tc.wantPass {
				require.NoError(t, err)
				assert.Contains(t, out, "PASS")
				return
			}
			require.ErrorIs(t, err, ErrVerifyFailed)
			assert.Contains(t, out, "FAIL")
		})
	}
}

// The vsa command binds the VSA to the artifacts the user holds.
func TestRunVSASubjects(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	k := newSigningKey(t, dir, "k")
	artifact := filepath.Join(dir, "image.tar")
	require.NoError(t, os.WriteFile(artifact, []byte("layers"), 0o600))
	vsaPath := signVSAFor(t, dir, "bound", "https://a.example.com", k, fileSHA256(t, artifact))
	other := filepath.Join(dir, "other.tar")
	require.NoError(t, os.WriteFile(other, []byte("not it"), 0o600))

	for _, tc := range []struct {
		name       string
		artifacts  []string
		subjects   []string
		wantPass   bool
		wantOutput []string
	}{
		{name: "no subjects", wantPass: true},
		{name: "held artifact", artifacts: []string{artifact}, wantPass: true, wantOutput: []string{"Subjects:", "[PASS]", "image.tar"}},
		{name: "stated digest", subjects: []string{"sha256:" + fileSHA256(t, artifact)}, wantPass: true, wantOutput: []string{"[PASS]"}},
		{name: "other artifact fails", artifacts: []string{artifact, other}, wantPass: false, wantOutput: []string{"[PASS]", "[FAIL]", "other.tar"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts, err := newVSAOptions(t, vsaPath, func(o *vsaOptions) {
				o.VerifierSpecs = []string{"https://a.example.com=" + k.spec}
				o.shared.PublicKeyPaths = []string{k.pemPath}
				o.ArtifactPaths = tc.artifacts
				o.SubjectSpecs = tc.subjects
			})
			require.NoError(t, err)
			out, err := runVSAWith(t, opts)
			for _, want := range tc.wantOutput {
				assert.Contains(t, out, want)
			}
			if tc.wantPass {
				require.NoError(t, err)
				assert.Contains(t, out, "PASS")
				return
			}
			require.ErrorIs(t, err, ErrVerifyFailed)
			assert.Contains(t, out, "FAIL")
		})
	}
}
