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
// It wraps GetOrCreateBotDeviceClient and NewBeeperStreamPublisher so callers don't need to
// duplicate device-provisioning and sender/publisher wiring.
// clientOpts.Purpose must be set by the caller.
func (as *AppService) NewBeeperStreamPublisher(
	ctx context.Context,
	clientOpts BotDeviceClientOptions,
	publisherOpts *mautrix.BeeperStreamPublisherOptions,
	senderOpts *mautrix.BeeperStreamSenderOptions,
) (*mautrix.BeeperStreamPublisher, error) {
	client, err := as.GetOrCreateBotDeviceClient(ctx, clientOpts)
	if err != nil {
		return nil, err
	}
	return client.NewBeeperStreamPublisher(publisherOpts, senderOpts), nil
}
