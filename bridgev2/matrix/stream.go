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
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/id"
)

func (br *Connector) GetOrCreateStreamHelper(ctx context.Context) (*mautrix.StreamHelper, error) {
	br.streamHelperLock.Lock()
	defer br.streamHelperLock.Unlock()
	if br.streamHelper != nil {
		return br.streamHelper, nil
	}
	client, err := br.getStreamClient(ctx)
	if err != nil {
		return nil, err
	}
	br.streamHelper = br.AS.GetOrCreateStreamHelper(client, &mautrix.StreamHelperOptions{
		Logger: br.Log,
	})
	return br.streamHelper, nil
}

func (br *Connector) getStreamClient(ctx context.Context) (*mautrix.Client, error) {
	if br.Crypto != nil {
		if client := br.Crypto.Client(); client != nil && client.DeviceID != "" {
			return client, nil
		}
	}
	if br.streamClient != nil && br.streamClient.DeviceID != "" {
		return br.streamClient, nil
	}
	client := br.AS.NewMautrixClient(br.AS.BotMXID())
	initialDeviceDisplayName := fmt.Sprintf("%s bridge stream", br.Bridge.Network.GetName().DisplayName)
	deviceID := id.DeviceID(br.Bridge.DB.KV.Get(ctx, database.KeyStreamDeviceID))
	if br.Config.Encryption.MSC4190 {
		if err := client.CreateDeviceMSC4190(ctx, deviceID, initialDeviceDisplayName); err != nil {
			return nil, fmt.Errorf("failed to create stream device for bridge bot: %w", err)
		}
	} else {
		flows, err := client.GetLoginFlows(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get supported login flows for stream device: %w", err)
		} else if !flows.HasFlow(mautrix.AuthTypeAppservice) {
			return nil, fmt.Errorf("homeserver does not support appservice login for stream device")
		}
		resp, err := client.Login(ctx, &mautrix.ReqLogin{
			Type: mautrix.AuthTypeAppservice,
			Identifier: mautrix.UserIdentifier{
				Type: mautrix.IdentifierTypeUser,
				User: string(br.AS.BotMXID()),
			},
			DeviceID:                 deviceID,
			StoreCredentials:         true,
			InitialDeviceDisplayName: initialDeviceDisplayName,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to log in bridge bot stream device: %w", err)
		}
		client.DeviceID = resp.DeviceID
	}
	br.Bridge.DB.KV.Set(ctx, database.KeyStreamDeviceID, client.DeviceID.String())
	br.streamClient = client
	return client, nil
}
