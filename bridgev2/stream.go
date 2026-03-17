// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"fmt"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
)

type beeperStreamBotClientProvider interface {
	BotClient() *mautrix.Client
}

func (br *Bridge) GetOrCreateBeeperStreamSender(ctx context.Context) (*mautrix.BeeperStreamSender, error) {
	br.beeperStreamLock.Lock()
	defer br.beeperStreamLock.Unlock()
	if br.beeperStreamSender != nil {
		return br.beeperStreamSender, nil
	}
	provider, ok := br.Matrix.(beeperStreamBotClientProvider)
	if !ok {
		return nil, fmt.Errorf("matrix connector doesn't expose a bot client")
	}
	client := provider.BotClient()
	if client == nil {
		return nil, fmt.Errorf("matrix connector doesn't have a bot client")
	}
	br.beeperStreamSender = client.GetOrCreateBeeperStreamSender(&mautrix.BeeperStreamSenderOptions{
		AuthorizeSubscriber: br.authorizeBeeperStreamSubscriber,
	})
	return br.beeperStreamSender, nil
}

func (br *Bridge) authorizeBeeperStreamSubscriber(ctx context.Context, req *mautrix.BeeperStreamSubscribeRequest) bool {
	user, err := br.GetUserByMXID(ctx, req.UserID)
	if err != nil {
		br.Log.Err(err).Stringer("sender", req.UserID).Msg("Failed to load beeper stream subscriber user")
		return false
	}
	if user == nil || !user.Permissions.SendEvents {
		return false
	}
	member, err := br.Matrix.GetMemberInfo(ctx, req.RoomID, req.UserID)
	if err != nil {
		br.Log.Err(err).
			Stringer("sender", req.UserID).
			Stringer("room_id", req.RoomID).
			Msg("Failed to load beeper stream subscriber membership")
		return false
	}
	return member != nil && member.Membership == event.MembershipJoin
}
