// Copyright (c) 2020 Nikos Filippakis
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"maunium.net/go/mautrix/id"
)

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
	csPubkeys := mach.GetOwnCrossSigningPublicKeys()
	if csPubkeys == nil {
		return false
	}
	if userID == mach.Client.UserID {
		return true
	}
	// first we verify our user-signing key
	sskSigs, err := mach.CryptoStore.GetSignaturesForKeyBy(mach.Client.UserID, csPubkeys.UserSigningKey, mach.Client.UserID)
	if err != nil {
		mach.Log.Error("Error retrieving our self-singing key signatures: %v", err)
		return false
	}
	if _, ok := sskSigs[csPubkeys.MasterKey]; !ok {
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
	sigExists, err := mach.CryptoStore.IsKeySignedBy(userID, theirMskKey, mach.Client.UserID, csPubkeys.UserSigningKey)
	if err != nil {
		mach.Log.Error("Error retrieving cross-singing signatures for master key of user %v from database: %v", userID, err)
		return false
	}
	return sigExists
}
