// SPDX-FileCopyrightText: Copyright 2026 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"errors"
	"fmt"

	sapi "github.com/policylabs/signer/api/v1"
)

// ErrIdentityMismatch is returned by VerifyIdentity when none of the
// expected identities match the envelope's verified signers. Like
// ErrSignatureRequired, it's a verification outcome — callers should
// translate it to their "verification failed" exit path rather than
// treating it as an execution error.
var ErrIdentityMismatch = errors.New("envelope signer does not match any expected identity")

// VerifyIdentity confirms that the envelope was signed by at least
// one identity in expected (OR semantics: any match is sufficient).
// The check is meaningful only for envelopes whose Verification
// implementation supports identity matching — primarily Sigstore
// bundles, where signing certificates carry subject identities.
//
// Returns ErrIdentityMismatch if no expected identity matches. If
// expected is empty, returns nil (no-op).
//
// Call VerifySignatures first: identity matching reads from the
// envelope's verified-signature material, which the envelope only
// populates once cryptographic verification has succeeded.
func (*Verifier) VerifyIdentity(env Envelope, expected []*sapi.Identity) error {
	if len(expected) == 0 {
		return nil
	}
	if env == nil {
		return errors.New("nil envelope")
	}
	ver := env.GetVerification()
	if ver == nil {
		return fmt.Errorf("%w: envelope exposes no verification material", ErrIdentityMismatch)
	}
	for _, id := range expected {
		if id == nil {
			continue
		}
		if ver.MatchesIdentity(id) {
			return nil
		}
	}
	return ErrIdentityMismatch
}
