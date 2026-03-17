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

func (login *UserLogin) GetOrCreateBeeperStreamPublisher(ctx context.Context) (*mautrix.BeeperStreamPublisher, error) {
	login.beeperStreamLock.Lock()
	defer login.beeperStreamLock.Unlock()
	if login.beeperStreamPublisher != nil {
		return login.beeperStreamPublisher, nil
	}
	provider, ok := login.Bridge.Matrix.(MatrixConnectorWithBeeperStream)
	if !ok {
		return nil, fmt.Errorf("matrix connector doesn't support beeper streams")
	}
	publisher, err := provider.GetOrCreateBeeperStreamPublisher(ctx, &mautrix.BeeperStreamPublisherOptions{
		AuthorizeSubscriber: login.authorizeBeeperStreamSubscriber,
	})
	if err != nil {
		return nil, err
	}
	login.beeperStreamPublisher = publisher
	return publisher, nil
}

func (login *UserLogin) authorizeBeeperStreamSubscriber(ctx context.Context, req *mautrix.BeeperStreamSubscribeRequest) bool {
	user, err := login.Bridge.GetUserByMXID(ctx, req.UserID)
	if err != nil {
		login.Log.Err(err).Stringer("sender", req.UserID).Msg("Failed to load beeper stream subscriber user")
		return false
	}
	if user == nil || !user.Permissions.SendEvents {
		return false
	}
	member, err := login.Bridge.Matrix.GetMemberInfo(ctx, req.RoomID, req.UserID)
	if err != nil {
		login.Log.Err(err).
			Stringer("sender", req.UserID).
			Stringer("room_id", req.RoomID).
			Msg("Failed to load beeper stream subscriber membership")
		return false
	}
	return member != nil && member.Membership == event.MembershipJoin
}
