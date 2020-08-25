// Copyright (c) 2020 Nikos Filippakis
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"github.com/pkg/errors"
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

// uploadCrossSigningKeysToServer uploads the given cached cross-signing keys to the server.
// It also creates and uploads the appropriate signatures for each key.
// It requires the user password for completing user-interactive authorization with the server.
func (mach *OlmMachine) uploadCrossSigningKeysToServer(keys *CrossSigningKeysCache, userPassword string) error {
	userID := mach.Client.UserID
	masterKeyID := id.NewKeyID(id.KeyAlgorithmEd25519, keys.MasterKey.PublicKey.String())
	masterKey := mautrix.CrossSigningKeys{
		UserID: userID,
		Usage:  []id.CrossSigningUsage{id.XSUsageMaster},
		Keys: map[id.KeyID]id.Ed25519{
			masterKeyID: keys.MasterKey.PublicKey,
		},
	}

	selfKey := mautrix.CrossSigningKeys{
		UserID: userID,
		Usage:  []id.CrossSigningUsage{id.XSUsageSelfSigning},
		Keys: map[id.KeyID]id.Ed25519{
			id.NewKeyID(id.KeyAlgorithmEd25519, keys.SelfSigningKey.PublicKey.String()): keys.SelfSigningKey.PublicKey,
		},
	}
	selfSig, err := keys.MasterKey.SignJSON(selfKey)
	if err != nil {
		return err
	}
	selfKey.Signatures = map[id.UserID]map[id.KeyID]string{
		userID: {
			masterKeyID: selfSig,
		},
	}
	mach.Log.Debug("Self-signing key signature: %v", selfSig)

	userKey := mautrix.CrossSigningKeys{
		UserID: userID,
		Usage:  []id.CrossSigningUsage{id.XSUsageUserSigning},
		Keys: map[id.KeyID]id.Ed25519{
			id.NewKeyID(id.KeyAlgorithmEd25519, keys.UserSigningKey.PublicKey.String()): keys.UserSigningKey.PublicKey,
		},
	}
	userSig, err := keys.MasterKey.SignJSON(userKey)
	if err != nil {
		return err
	}
	userKey.Signatures = map[id.UserID]map[id.KeyID]string{
		userID: {
			masterKeyID: userSig,
		},
	}
	mach.Log.Debug("User-signing key signature: %v", userSig)

	req := &mautrix.UploadCrossSigningKeysReq{
		Master:      masterKey,
		SelfSigning: selfKey,
		UserSigning: userKey,
	}

	return mach.Client.UploadCrossSigningKeys(req, func(uiResp *mautrix.RespUserInteractive) interface{} {
		return mautrix.ReqUIAuthLogin{
			BaseAuthData: mautrix.BaseAuthData{
				Type:    mautrix.AuthTypePassword,
				Session: uiResp.Session,
			},
			User:     mach.Client.UserID.String(),
			Password: userPassword,
		}
	})
}

// SignUserAndUpload creates a cross-signing signature for a user, stores it and uploads it to the server.
func (mach *OlmMachine) SignUserAndUpload(userID id.UserID) error {
	if mach.crossSigningKeys == nil {
		return errors.New("No cross-signing keys found")
	}
	if userID == mach.Client.UserID {
		return nil
	}

	keys, err := mach.CryptoStore.GetCrossSigningKeys(userID)
	if err != nil {
		return err
	}
	masterKey, ok := keys[id.XSUsageMaster]
	if !ok {
		return errors.Errorf("No master key found for user %v", userID)
	}

	userSigningKey := mach.crossSigningKeys.UserSigningKey
	masterKeyObj := mautrix.ReqKeysSignatures{
		UserID: userID,
		Usage:  []id.CrossSigningUsage{id.XSUsageMaster},
		Keys: map[id.KeyID]id.Ed25519{
			id.NewKeyID(id.KeyAlgorithmEd25519, masterKey.String()): masterKey,
		},
	}
	signature, err := userSigningKey.SignJSON(masterKeyObj)
	if err != nil {
		return err
	}
	masterKeyObj.Signatures = mautrix.Signatures{
		mach.Client.UserID: map[id.KeyID]string{
			id.NewKeyID(id.KeyAlgorithmEd25519, userSigningKey.PublicKey.String()): signature,
		},
	}
	mach.Log.Trace("Signed master key for user %v: `%v`", userID, signature)

	resp, err := mach.Client.UploadSignatures(&mautrix.ReqUploadSignatures{
		userID: map[string]mautrix.ReqKeysSignatures{
			masterKey.String(): masterKeyObj,
		},
	})

	if err != nil {
		return err
	}
	if len(resp.Failures) > 0 {
		return errors.Errorf("Key uploading failures: %v", resp.Failures)
	}

	if err := mach.CryptoStore.PutSignature(userID, masterKey, mach.Client.UserID, userSigningKey.PublicKey, signature); err != nil {
		return err
	}

	return nil
}

// SignDeviceAndUpload creates a cross-signing signature for a device, stores it and uploads it to the server.
func (mach *OlmMachine) SignDeviceAndUpload(device *DeviceIdentity) error {
	return nil
}
