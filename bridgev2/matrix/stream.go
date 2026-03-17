// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"context"
	"fmt"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/id"
)

const streamBotDeviceKey database.Key = "stream_device_id"

func (br *Connector) GetOrCreateStreamHelper(ctx context.Context) (*mautrix.StreamHelper, error) {
	client, err := br.getStreamClient(ctx)
	if err != nil {
		return nil, err
	}
	return client.GetOrCreateStreamHelper(&mautrix.StreamHelperOptions{Logger: br.Log}), nil
}

func (br *Connector) getStreamClient(ctx context.Context) (*mautrix.Client, error) {
	if br.Crypto != nil {
		if client := br.Crypto.Client(); client != nil && client.DeviceID != "" {
			return client, nil
		}
	}
	return br.AS.GetOrCreateBotDeviceClient(ctx, appservice.BotDeviceClientOptions{
		Key:                      "stream",
		InitialDeviceDisplayName: fmt.Sprintf("%s bridge stream", br.Bridge.Network.GetName().DisplayName),
		MSC4190:                  br.Config.Encryption.MSC4190,
		LoadDeviceID: func(ctx context.Context) (id.DeviceID, error) {
			return id.DeviceID(br.Bridge.DB.KV.Get(ctx, streamBotDeviceKey)), nil
		},
		SaveDeviceID: func(ctx context.Context, deviceID id.DeviceID) error {
			br.Bridge.DB.KV.Set(ctx, streamBotDeviceKey, deviceID.String())
			return nil
		},
	})
}
