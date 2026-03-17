// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package appservice

import (
	"context"
	"fmt"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
)

// BotDeviceClientOptions configures [AppService.GetOrCreateBotDeviceClient].
type BotDeviceClientOptions struct {
	// Key is the cache key for this device-bearing bot client.
	Key string
	// UserID defaults to [AppService.BotMXID].
	UserID id.UserID
	// InitialDeviceDisplayName is used when creating a new device.
	InitialDeviceDisplayName string
	// MSC4190 toggles device creation via MSC4190 instead of appservice login.
	MSC4190 bool
	// LoadDeviceID loads a previously persisted device ID for reuse.
	LoadDeviceID func(context.Context) (id.DeviceID, error)
	// SaveDeviceID persists the final device ID after provisioning.
	SaveDeviceID func(context.Context, id.DeviceID) error
}

// GetOrCreateBotDeviceClient creates or reuses a device-bearing appservice bot client.
func (as *AppService) GetOrCreateBotDeviceClient(ctx context.Context, opts BotDeviceClientOptions) (*mautrix.Client, error) {
	if opts.Key == "" {
		return nil, fmt.Errorf("missing bot device client key")
	}
	as.botDeviceClientsLock.RLock()
	client := as.botDeviceClients[opts.Key]
	as.botDeviceClientsLock.RUnlock()
	if client != nil && client.DeviceID != "" {
		return client, nil
	}

	as.botDeviceClientsLock.Lock()
	defer as.botDeviceClientsLock.Unlock()
	client = as.botDeviceClients[opts.Key]
	if client != nil && client.DeviceID != "" {
		return client, nil
	}

	userID := opts.UserID
	if userID == "" {
		userID = as.BotMXID()
	}
	if opts.InitialDeviceDisplayName == "" {
		return nil, fmt.Errorf("missing initial device display name")
	}

	storedDeviceID := id.DeviceID("")
	if opts.LoadDeviceID != nil {
		var err error
		storedDeviceID, err = opts.LoadDeviceID(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to load stored device ID: %w", err)
		}
	}

	client = as.NewMautrixClient(userID)
	if opts.MSC4190 {
		if err := client.CreateDeviceMSC4190(ctx, storedDeviceID, opts.InitialDeviceDisplayName); err != nil {
			return nil, fmt.Errorf("failed to create bot device with MSC4190: %w", err)
		}
	} else if storedDeviceID != "" {
		client.DeviceID = storedDeviceID
		client.SetAppServiceDeviceID = true
	} else {
		flows, err := client.GetLoginFlows(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get supported login flows for bot device: %w", err)
		} else if !flows.HasFlow(mautrix.AuthTypeAppservice) {
			return nil, fmt.Errorf("homeserver does not support appservice login for bot device")
		}
		resp, err := client.Login(ctx, &mautrix.ReqLogin{
			Type: mautrix.AuthTypeAppservice,
			Identifier: mautrix.UserIdentifier{
				Type: mautrix.IdentifierTypeUser,
				User: string(userID),
			},
			StoreCredentials:         true,
			InitialDeviceDisplayName: opts.InitialDeviceDisplayName,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to log in bot device: %w", err)
		}
		client.DeviceID = resp.DeviceID
	}

	if opts.SaveDeviceID != nil {
		if err := opts.SaveDeviceID(ctx, client.DeviceID); err != nil {
			return nil, fmt.Errorf("failed to persist bot device ID: %w", err)
		}
	}

	as.botDeviceClients[opts.Key] = client
	return client, nil
}
