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
