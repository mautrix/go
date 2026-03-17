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

// NewBeeperStreamPublisher returns a stream publisher backed by a device-bearing bot client.
// It wraps GetOrCreateBotDeviceClient and NewBeeperStreamPublisher so that non-bridge bots
// do not need to duplicate the device-provisioning wiring.
// opts.Purpose must be set by the caller.
func (as *AppService) NewBeeperStreamPublisher(
	ctx context.Context,
	opts BotDeviceClientOptions,
	authorizeSubscriber func(context.Context, *mautrix.BeeperStreamSubscribeRequest) bool,
) (*mautrix.BeeperStreamPublisher, error) {
	client, err := as.GetOrCreateBotDeviceClient(ctx, opts)
	if err != nil {
		return nil, err
	}
	return client.NewBeeperStreamPublisher(
		&mautrix.BeeperStreamPublisherOptions{AuthorizeSubscriber: authorizeSubscriber},
		nil,
	), nil
}
