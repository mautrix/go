// Copyright (c) 2020 Nikos Filippakis
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
		for _, key := range userKeys.Keys {
			for _, usage := range userKeys.Usage {
				mach.Log.Debug("Storing cross-signing key for %v: %v (type %v)", userID, key, usage)
				if err := mach.CryptoStore.PutCrossSigningKey(userID, usage, key); err != nil {
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
							mach.Log.Debug("Treating %v as the device name", signKeyName)
						}
					}

					mach.Log.Debug("Verifying %v with: %v %v %v", userKeys, signUserID, signKeyName, signingKey)
					if verified, err := olm.VerifySignatureJSON(userKeys, signUserID, signKeyName, signingKey); err != nil {
						mach.Log.Error("Error while verifying cross-signing keys: %v", err)
					} else {
						if verified {
							mach.Log.Debug("Cross-signing keys verified")
							mach.CryptoStore.PutSignature(userID, key, signUserID, signingKey, signature)
						} else {
							mach.Log.Error("Cross-signing keys verification unsuccessful", err)
						}
					}
				}
			}
		}
	}
}

// IsDeviceTrusted returns whether a device has been determined to be trusted either through verification or cross-signing.
func (mach *OlmMachine) IsDeviceTrusted(device *DeviceIdentity) bool {
	userID := device.UserID
	if device.Trust == TrustStateVerified {
		return true
	} else if device.Trust == TrustStateBlacklisted {
		return false
	}
	if !mach.IsUserTrusted(userID) {
		return false
	}

	theirKeys, err := mach.CryptoStore.GetCrossSigningKeys(userID)
	if err != nil {
		mach.Log.Error("Error retrieving cross-singing key of user %v from database: %v", userID, err)
		return false
	}
	theirMSK, ok := theirKeys[id.XSUsageMaster]
	if !ok {
		mach.Log.Error("Master key of user %v not found", userID)
		return false
	}
	theirSSK, ok := theirKeys[id.XSUsageSelfSigning]
	if !ok {
		mach.Log.Error("Self-signing key of user %v not found", userID)
		return false
	}
	sskSigExists, err := mach.CryptoStore.IsKeySignedBy(userID, theirSSK, userID, theirMSK)
	if err != nil {
		mach.Log.Error("Error retrieving cross-singing signatures for master key of user %v from database: %v", userID, err)
		return false
	}
	if !sskSigExists {
		mach.Log.Warn("Self-signing key of user %v is not signed by their master key", userID)
		return false
	}
	deviceSigExists, err := mach.CryptoStore.IsKeySignedBy(userID, device.SigningKey, userID, theirSSK)
	if err != nil {
		mach.Log.Error("Error retrieving cross-singing signatures for master key of user %v from database: %v", userID, err)
		return false
	}
	return deviceSigExists
}

// IsUserTrusted returns whether a user has been determined to be trusted by our user-signing key having signed their master key.
// In the case the user ID is our own and we have successfully retrieved our cross-signing keys, we trust our own user.
func (mach *OlmMachine) IsUserTrusted(userID id.UserID) bool {
	if mach.crossSigningKeys == nil {
		return false
	}
	if userID == mach.Client.UserID {
		return true
	}
	// first we verify our user-signing key
	sskSigs, err := mach.CryptoStore.GetSignaturesForKeyBy(mach.Client.UserID, mach.crossSigningKeys.UserSigningKey.PublicKey, mach.Client.UserID)
	if err != nil {
		mach.Log.Error("Error retrieving our self-singing key signatures: %v", err)
		return false
	}
	if _, ok := sskSigs[mach.crossSigningKeys.MasterKey.PublicKey]; !ok {
		// our user-signing key was not signed by our master key
		return false
	}
	theirKeys, err := mach.CryptoStore.GetCrossSigningKeys(userID)
	if err != nil {
		mach.Log.Error("Error retrieving cross-singing key of user %v from database: %v", userID, err)
		return false
	}
	theirMskKey, ok := theirKeys[id.XSUsageMaster]
	if !ok {
		mach.Log.Error("Master key of user %v not found", userID)
		return false
	}
	sigExists, err := mach.CryptoStore.IsKeySignedBy(userID, theirMskKey, mach.Client.UserID, mach.crossSigningKeys.UserSigningKey.PublicKey)
	if err != nil {
		mach.Log.Error("Error retrieving cross-singing signatures for master key of user %v from database: %v", userID, err)
		return false
	}
	return sigExists
}
