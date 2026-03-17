// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package appservice

import (
	"context"
	"fmt"
	"sync"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
)

// BotDeviceClientOptions configures [AppService.GetOrCreateBotDeviceClient].
type BotDeviceClientOptions struct {
	// Purpose is the cache key.
	Purpose string
	// InitialDeviceDisplayName is used when creating a device.
	InitialDeviceDisplayName string
	// MSC4190 uses MSC4190 instead of appservice login.
	MSC4190 bool
	// LoadDeviceID loads a persisted device ID.
	LoadDeviceID func(context.Context) (id.DeviceID, error)
	// SaveDeviceID persists the device ID.
	SaveDeviceID func(context.Context, id.DeviceID) error
}

// GetOrCreateBotDeviceClient creates or reuses a device-bearing appservice bot client.
func (as *AppService) GetOrCreateBotDeviceClient(ctx context.Context, opts BotDeviceClientOptions) (*mautrix.Client, error) {
	if opts.Purpose == "" {
		return nil, fmt.Errorf("missing bot device client purpose")
	}
	as.botDeviceClientsLock.RLock()
	client := as.botDeviceClientsByPurpose[opts.Purpose]
	as.botDeviceClientsLock.RUnlock()
	if client != nil && client.DeviceID != "" {
		return client, nil
	}

	lock := as.getBotDeviceClientLock(opts.Purpose)
	lock.Lock()
	defer lock.Unlock()

	as.botDeviceClientsLock.RLock()
	client = as.botDeviceClientsByPurpose[opts.Purpose]
	as.botDeviceClientsLock.RUnlock()
	if client != nil && client.DeviceID != "" {
		return client, nil
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

	client = as.NewMautrixClient(as.BotMXID())
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
				User: string(as.BotMXID()),
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

	as.botDeviceClientsLock.Lock()
	as.botDeviceClientsByPurpose[opts.Purpose] = client
	as.botDeviceClientsLock.Unlock()
	return client, nil
}

func (as *AppService) getBotDeviceClientLock(purpose string) *sync.Mutex {
	as.botDeviceClientLocksLock.Lock()
	defer as.botDeviceClientLocksLock.Unlock()
	lock := as.botDeviceClientLocks[purpose]
	if lock == nil {
		lock = &sync.Mutex{}
		as.botDeviceClientLocks[purpose] = lock
	}
	return lock
}

// GetOrCreateBeeperStreamSender returns a stream sender for a bot device client.
// clientOpts.Purpose must be set.
func (as *AppService) GetOrCreateBeeperStreamSender(
	ctx context.Context,
	clientOpts BotDeviceClientOptions,
	senderOpts *mautrix.BeeperStreamSenderOptions,
) (*mautrix.BeeperStreamSender, error) {
	client, err := as.GetOrCreateBotDeviceClient(ctx, clientOpts)
	if err != nil {
		return nil, err
	}
	return client.GetOrCreateBeeperStreamSender(senderOpts), nil
}
