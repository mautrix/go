// Copyright (c) 2020 Nikos Filippakis
// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"

	"github.com/element-hq/mautrix-go/id"
)

func (mach *OlmMachine) ResolveTrust(device *id.Device) id.TrustState {
	state, _ := mach.ResolveTrustContext(context.Background(), device)
	return state
}

// ResolveTrustContext resolves the trust state of the device from cross-signing.
func (mach *OlmMachine) ResolveTrustContext(ctx context.Context, device *id.Device) (id.TrustState, error) {
	if device.Trust == id.TrustStateVerified || device.Trust == id.TrustStateBlacklisted {
		return device.Trust, nil
	}
	theirKeys, err := mach.CryptoStore.GetCrossSigningKeys(ctx, device.UserID)
	if err != nil {
		mach.machOrContextLog(ctx).Error().Err(err).
			Str("user_id", device.UserID.String()).
			Msg("Error retrieving cross-signing key of user from database")
		return id.TrustStateUnset, err
	}
	theirMSK, ok := theirKeys[id.XSUsageMaster]
	if !ok {
		mach.machOrContextLog(ctx).Error().
			Str("user_id", device.UserID.String()).
			Msg("Master key of user not found")
		return id.TrustStateUnset, nil
	}
	theirSSK, ok := theirKeys[id.XSUsageSelfSigning]
	if !ok {
		mach.machOrContextLog(ctx).Error().
			Str("user_id", device.UserID.String()).
			Msg("Self-signing key of user not found")
		return id.TrustStateUnset, nil
	}
	sskSigExists, err := mach.CryptoStore.IsKeySignedBy(ctx, device.UserID, theirSSK.Key, device.UserID, theirMSK.Key)
	if err != nil {
		mach.machOrContextLog(ctx).Error().Err(err).
			Str("user_id", device.UserID.String()).
			Msg("Error retrieving cross-signing signatures for master key of user from database")
		return id.TrustStateUnset, err
	}
	if !sskSigExists {
		mach.machOrContextLog(ctx).Error().
			Str("user_id", device.UserID.String()).
			Msg("Self-signing key of user is not signed by their master key")
		return id.TrustStateUnset, nil
	}
	deviceSigExists, err := mach.CryptoStore.IsKeySignedBy(ctx, device.UserID, device.SigningKey, device.UserID, theirSSK.Key)
	if err != nil {
		mach.machOrContextLog(ctx).Error().Err(err).
			Str("user_id", device.UserID.String()).
			Str("device_key", device.SigningKey.String()).
			Msg("Error retrieving cross-signing signatures for device from database")
		return id.TrustStateUnset, err
	}
	if deviceSigExists {
		if trusted, err := mach.IsUserTrusted(ctx, device.UserID); !trusted {
			return id.TrustStateCrossSignedVerified, err
		} else if theirMSK.Key == theirMSK.First {
			return id.TrustStateCrossSignedTOFU, nil
		}
		return id.TrustStateCrossSignedUntrusted, nil
	}
	return id.TrustStateUnset, nil
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
func (mach *OlmMachine) IsUserTrusted(ctx context.Context, userID id.UserID) (bool, error) {
	csPubkeys := mach.GetOwnCrossSigningPublicKeys(ctx)
	if csPubkeys == nil {
		return false, nil
	}
	if userID == mach.Client.UserID {
		return true, nil
	}
	// first we verify our user-signing key
	ourUserSigningKeyTrusted, err := mach.CryptoStore.IsKeySignedBy(ctx, mach.Client.UserID, csPubkeys.UserSigningKey, mach.Client.UserID, csPubkeys.MasterKey)
	if err != nil {
		mach.machOrContextLog(ctx).Error().Err(err).Msg("Error retrieving our self-signing key signatures from database")
		return false, err
	} else if !ourUserSigningKeyTrusted {
		return false, nil
	}
	theirKeys, err := mach.CryptoStore.GetCrossSigningKeys(ctx, userID)
	if err != nil {
		mach.machOrContextLog(ctx).Error().Err(err).
			Str("user_id", userID.String()).
			Msg("Error retrieving cross-signing key of user from database")
		return false, err
	}
	theirMskKey, ok := theirKeys[id.XSUsageMaster]
	if !ok {
		mach.machOrContextLog(ctx).Error().
			Str("user_id", userID.String()).
			Msg("Master key of user not found")
		return false, nil
	}
	sigExists, err := mach.CryptoStore.IsKeySignedBy(ctx, userID, theirMskKey.Key, mach.Client.UserID, csPubkeys.UserSigningKey)
	if err != nil {
		mach.machOrContextLog(ctx).Error().Err(err).
			Str("user_id", userID.String()).
			Msg("Error retrieving cross-signing signatures for master key of user from database")
		return false, err
	}
	return sigExists, nil
}
