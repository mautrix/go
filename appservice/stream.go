// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package appservice

import (
	"context"

	"maunium.net/go/mautrix"
)

// GetOrCreateBeeperStreamPublisher returns a stream publisher backed by a device-bearing bot client.
// It wraps GetOrCreateBotDeviceClient and NewBeeperStreamPublisher so that non-bridge bots
// do not need to duplicate the device-provisioning wiring.
func (as *AppService) GetOrCreateBeeperStreamPublisher(
	ctx context.Context,
	opts BotDeviceClientOptions,
	authorizeSubscriber func(context.Context, *mautrix.BeeperStreamSubscribeRequest) bool,
) (*mautrix.BeeperStreamPublisher, error) {
	if opts.Purpose == "" {
		opts.Purpose = "stream"
	}
	client, err := as.GetOrCreateBotDeviceClient(ctx, opts)
	if err != nil {
		return nil, err
	}
	return client.NewBeeperStreamPublisher(
		&mautrix.BeeperStreamPublisherOptions{AuthorizeSubscriber: authorizeSubscriber},
		nil,
	), nil
}
