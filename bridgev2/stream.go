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

func (br *Bridge) GetOrCreateBeeperStreamSender() (*mautrix.BeeperStreamSender, error) {
	br.beeperStreamLock.Lock()
	defer br.beeperStreamLock.Unlock()
	if br.beeperStreamSender != nil {
		return br.beeperStreamSender, nil
	}
	connector, ok := br.Matrix.(MatrixConnectorWithBeeperStreamSender)
	if !ok {
		return nil, fmt.Errorf("matrix connector doesn't support beeper stream sender")
	}
	br.beeperStreamSender = connector.GetOrCreateBeeperStreamSender(&mautrix.BeeperStreamSenderOptions{
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
