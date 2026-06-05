// Copyright (c) 2026 Jonathan Page (benmichael)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"fmt"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/signatures"
	"maunium.net/go/mautrix/id"
)

// MSC4350ImpersonatableDeviceID is the stable device ID we use for each
// ghost user's impersonatable device. Using a constant means a re-upload
// over the same device ID is treated as an idempotent refresh by the
// homeserver instead of accumulating a new device per restart.
//
// The exact value is opaque to the protocol; clients only care that it
// matches the device_id embedded inside an event encrypted via the
// impersonator path.
const MSC4350ImpersonatableDeviceID id.DeviceID = "MSC4350IMPERSONATABLE"

// ImpersonatorSigner is the subset of crypto.OlmAccount used by
// BuildImpersonatableDeviceKeys. Defined here so tests can substitute a
// deterministic signer without standing up a full Olm account.
type ImpersonatorSigner interface {
	SignJSON(obj any) (string, error)
}

// BuildImpersonatableDeviceKeys constructs (but does not upload) a valid
// MSC4350 impersonatable device entry for the given ghost user, with the
// bridge bot embedded as the impersonator and a signature produced by
// signer (which MUST be the bot's Olm signing key).
//
// The returned DeviceKeys is ready to be PUT via /keys/upload while
// masquerading as ghostUserID (per MSC4326). It satisfies the structural
// requirements of MSC4350:
//   - algorithms: []
//   - keys: {}
//   - fi.mau.msc4350.impersonator: bot device-keys-like object (no
//     signatures field, per spec)
//   - signatures: a single signature from the bot's ed25519 device key
//
// Signing is performed over the canonical JSON form of the entry minus
// its own signatures and unsigned fields, matching Synapse's verification
// path implemented in handlers/e2e_keys.py._handle_msc4350_impersonator.
func BuildImpersonatableDeviceKeys(
	signer ImpersonatorSigner,
	ghostUserID id.UserID,
	ghostDeviceID id.DeviceID,
	botUserID id.UserID,
	botDeviceID id.DeviceID,
	botSigningKey id.SigningKey,
	botIdentityKey id.IdentityKey,
) (*mautrix.DeviceKeys, error) {
	if signer == nil {
		return nil, fmt.Errorf("impersonator signer is required")
	}
	if ghostUserID == "" || ghostDeviceID == "" {
		return nil, fmt.Errorf("ghost user_id and device_id are required")
	}
	if botUserID == "" || botDeviceID == "" {
		return nil, fmt.Errorf("bot user_id and device_id are required")
	}
	if botSigningKey == "" || botIdentityKey == "" {
		return nil, fmt.Errorf("bot signing_key and identity_key are required")
	}

	impersonatable := &mautrix.DeviceKeys{
		UserID:     ghostUserID,
		DeviceID:   ghostDeviceID,
		Algorithms: []id.Algorithm{},
		Keys:       mautrix.KeyMap{},
		MSC4350Impersonator: &mautrix.ImpersonatorDevice{
			UserID:   botUserID,
			DeviceID: botDeviceID,
			Algorithms: []id.Algorithm{
				id.AlgorithmMegolmV1,
				id.AlgorithmOlmV1,
			},
			Keys: mautrix.KeyMap{
				id.NewDeviceKeyID(id.KeyAlgorithmCurve25519, botDeviceID): string(botIdentityKey),
				id.NewDeviceKeyID(id.KeyAlgorithmEd25519, botDeviceID):    string(botSigningKey),
			},
		},
	}

	sig, err := signer.SignJSON(impersonatable)
	if err != nil {
		return nil, fmt.Errorf("sign impersonatable device: %w", err)
	}

	impersonatable.Signatures = signatures.NewSingleSignature(
		botUserID,
		id.KeyAlgorithmEd25519,
		botDeviceID.String(),
		sig,
	)
	return impersonatable, nil
}
