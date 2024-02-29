// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"
	"fmt"

	"github.com/element-hq/mautrix-go"
	"github.com/element-hq/mautrix-go/id"
)

type CrossSigningPublicKeysCache struct {
	MasterKey      id.Ed25519
	SelfSigningKey id.Ed25519
	UserSigningKey id.Ed25519
}

func (mach *OlmMachine) GetOwnCrossSigningPublicKeys(ctx context.Context) *CrossSigningPublicKeysCache {
	if mach.crossSigningPubkeys != nil {
		return mach.crossSigningPubkeys
	}
	if mach.CrossSigningKeys != nil {
		mach.crossSigningPubkeys = mach.CrossSigningKeys.PublicKeys()
		return mach.crossSigningPubkeys
	}
	if mach.crossSigningPubkeysFetched {
		return nil
	}
	cspk, err := mach.GetCrossSigningPublicKeys(ctx, mach.Client.UserID)
	if err != nil {
		mach.Log.Error().Err(err).Msg("Failed to get own cross-signing public keys")
		return nil
	}
	mach.crossSigningPubkeys = cspk
	mach.crossSigningPubkeysFetched = true
	return mach.crossSigningPubkeys
}

func (mach *OlmMachine) GetCrossSigningPublicKeys(ctx context.Context, userID id.UserID) (*CrossSigningPublicKeysCache, error) {
	dbKeys, err := mach.CryptoStore.GetCrossSigningKeys(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get keys from database: %w", err)
	}
	if len(dbKeys) > 0 {
		masterKey, ok := dbKeys[id.XSUsageMaster]
		if ok {
			selfSigning, _ := dbKeys[id.XSUsageSelfSigning]
			userSigning, _ := dbKeys[id.XSUsageUserSigning]
			return &CrossSigningPublicKeysCache{
				MasterKey:      masterKey.Key,
				SelfSigningKey: selfSigning.Key,
				UserSigningKey: userSigning.Key,
			}, nil
		}
	}

	keys, err := mach.Client.QueryKeys(ctx, &mautrix.ReqQueryKeys{
		DeviceKeys: mautrix.DeviceKeysRequest{
			userID: mautrix.DeviceIDList{},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query keys: %w", err)
	}

	var cspk CrossSigningPublicKeysCache

	masterKeys, ok := keys.MasterKeys[userID]
	if !ok {
		return nil, nil
	}
	cspk.MasterKey = masterKeys.FirstKey()

	selfSigningKeys, ok := keys.SelfSigningKeys[userID]
	if !ok {
		return nil, nil
	}
	cspk.SelfSigningKey = selfSigningKeys.FirstKey()

	userSigningKeys, ok := keys.UserSigningKeys[userID]
	if ok {
		cspk.UserSigningKey = userSigningKeys.FirstKey()
	}
	return &cspk, nil
}
