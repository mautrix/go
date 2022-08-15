// Copyright (c) 2020 Nikos Filippakis
// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/id"
)

func (mach *OlmMachine) storeCrossSigningKeys(crossSigningKeys map[id.UserID]mautrix.CrossSigningKeys, deviceKeys map[id.UserID]map[id.DeviceID]mautrix.DeviceKeys) {
	for userID, userKeys := range crossSigningKeys {
		currentKeys, err := mach.CryptoStore.GetCrossSigningKeys(userID)
		if err != nil {
			mach.Log.Error("Error fetching current cross-signing keys of user %v: %v", userID, err)
		}
		if currentKeys != nil {
			for curKeyUsage, curKey := range currentKeys {
				// got a new key with the same usage as an existing key
				for _, newKeyUsage := range userKeys.Usage {
					if newKeyUsage == curKeyUsage {
						if _, ok := userKeys.Keys[id.NewKeyID(id.KeyAlgorithmEd25519, curKey.Key.String())]; !ok {
							// old key is not in the new key map, so we drop signatures made by it
							if count, err := mach.CryptoStore.DropSignaturesByKey(userID, curKey.Key); err != nil {
								mach.Log.Error("Error deleting old signatures made by %s (%s): %v", curKey, curKeyUsage, err)
							} else {
								mach.Log.Debug("Dropped %d signatures made by key %s (%s) as it has been replaced", count, curKey, curKeyUsage)
							}
						}
						break
					}
				}
			}
		}

		for _, key := range userKeys.Keys {
			for _, usage := range userKeys.Usage {
				mach.Log.Debug("Storing cross-signing key for %s: %s (type %s)", userID, key, usage)
				if err = mach.CryptoStore.PutCrossSigningKey(userID, usage, key); err != nil {
					mach.Log.Error("Error storing cross-signing key: %v", err)
				}
			}

			for signUserID, keySigs := range userKeys.Signatures {
				for signKeyID, signature := range keySigs {
					_, signKeyName := signKeyID.Parse()
					signingKey := id.Ed25519(signKeyName)
					// if the signer is one of this user's own devices, find the key from the key ID
					if signUserID == userID {
						ownDeviceID := id.DeviceID(signKeyName)
						if ownDeviceKeys, ok := deviceKeys[userID][ownDeviceID]; ok {
							signingKey = ownDeviceKeys.Keys.GetEd25519(ownDeviceID)
							mach.Log.Trace("Treating %s as the device ID -> signing key %s", signKeyName, signingKey)
						}
					}
					if len(signingKey) != 43 {
						mach.Log.Trace("Cross-signing key %s/%s/%v has a signature from an unknown key %s", userID, key, userKeys.Usage, signKeyID)
						continue
					}

					mach.Log.Debug("Verifying cross-signing key %s/%s/%v with key %s/%s", userID, key, userKeys.Usage, signUserID, signingKey)
					if verified, err := olm.VerifySignatureJSON(userKeys, signUserID, signKeyName, signingKey); err != nil {
						mach.Log.Warn("Error while verifying signature from %s for %s: %v", signingKey, key, err)
					} else {
						if verified {
							mach.Log.Debug("Signature from %s for %s verified", signingKey, key)
							err = mach.CryptoStore.PutSignature(userID, key, signUserID, signingKey, signature)
							if err != nil {
								mach.Log.Warn("Failed to store signature from %s for %s: %v", signingKey, key, err)
							}
						} else {
							mach.Log.Error("Invalid signature from %s for %s", signingKey, key)
						}
					}
				}
			}
		}
	}
}
