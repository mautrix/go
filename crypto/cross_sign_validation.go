// Copyright (c) 2020 Nikos Filippakis
// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"maunium.net/go/mautrix/id"
)

// ResolveTrust resolves the trust state of the device from cross-signing.
func (mach *OlmMachine) ResolveTrust(device *id.Device) id.TrustState {
	if device.Trust == id.TrustStateVerified || device.Trust == id.TrustStateBlacklisted {
		return device.Trust
	}
	theirKeys, err := mach.CryptoStore.GetCrossSigningKeys(device.UserID)
	if err != nil {
		mach.Log.Error("Error retrieving cross-singing key of user %v from database: %v", device.UserID, err)
		return id.TrustStateUnset
	}
	theirMSK, ok := theirKeys[id.XSUsageMaster]
	if !ok {
		mach.Log.Error("Master key of user %v not found", device.UserID)
		return id.TrustStateUnset
	}
	theirSSK, ok := theirKeys[id.XSUsageSelfSigning]
	if !ok {
		mach.Log.Error("Self-signing key of user %v not found", device.UserID)
		return id.TrustStateUnset
	}
	sskSigExists, err := mach.CryptoStore.IsKeySignedBy(device.UserID, theirSSK.Key, device.UserID, theirMSK.Key)
	if err != nil {
		mach.Log.Error("Error retrieving cross-singing signatures for master key of user %v from database: %v", device.UserID, err)
		return id.TrustStateUnset
	}
	if !sskSigExists {
		mach.Log.Warn("Self-signing key of user %v is not signed by their master key", device.UserID)
		return id.TrustStateUnset
	}
	deviceSigExists, err := mach.CryptoStore.IsKeySignedBy(device.UserID, device.SigningKey, device.UserID, theirSSK.Key)
	if err != nil {
		mach.Log.Error("Error retrieving cross-singing signatures for master key of user %v from database: %v", device.UserID, err)
		return id.TrustStateUnset
	}
	if deviceSigExists {
		if mach.IsUserTrusted(device.UserID) {
			return id.TrustStateCrossSignedVerified
		} else if theirMSK.Key == theirMSK.First {
			return id.TrustStateCrossSignedTOFU
		}
		return id.TrustStateCrossSignedUntrusted
	}
	return id.TrustStateUnset
}

// IsDeviceTrusted returns whether a device has been determined to be trusted either through verification or cross-signing.
func (mach *OlmMachine) IsDeviceTrusted(device *id.Device) bool {
	switch mach.ResolveTrust(device) {
	case id.TrustStateVerified, id.TrustStateCrossSignedTOFU, id.TrustStateCrossSignedVerified:
		return true
	default:
		return false
	}
}

// IsUserTrusted returns whether a user has been determined to be trusted by our user-signing key having signed their master key.
// In the case the user ID is our own and we have successfully retrieved our cross-signing keys, we trust our own user.
func (mach *OlmMachine) IsUserTrusted(userID id.UserID) bool {
	csPubkeys := mach.GetOwnCrossSigningPublicKeys()
	if csPubkeys == nil {
		return false
	}
	if userID == mach.Client.UserID {
		return true
	}
	// first we verify our user-signing key
	ourUserSigningKeyTrusted, err := mach.CryptoStore.IsKeySignedBy(mach.Client.UserID, csPubkeys.UserSigningKey, mach.Client.UserID, csPubkeys.MasterKey)
	if err != nil {
		mach.Log.Error("Error retrieving our self-singing key signatures: %v", err)
		return false
	} else if !ourUserSigningKeyTrusted {
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
	sigExists, err := mach.CryptoStore.IsKeySignedBy(userID, theirMskKey.Key, mach.Client.UserID, csPubkeys.UserSigningKey)
	if err != nil {
		mach.Log.Error("Error retrieving cross-singing signatures for master key of user %v from database: %v", userID, err)
		return false
	}
	return sigExists
}
