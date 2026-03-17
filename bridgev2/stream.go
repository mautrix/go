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

// streamGeneratorProvider is the narrow capability interface for matrix connectors that support streams.
type streamGeneratorProvider interface {
	GetOrCreateStreamGenerator(ctx context.Context, opts *mautrix.StreamGeneratorOptions) (*mautrix.StreamGenerator, error)
}

// GetStreamGenerator returns this login's *mautrix.StreamGenerator, initializing it lazily.
func (login *UserLogin) GetStreamGenerator(ctx context.Context) (*mautrix.StreamGenerator, error) {
	login.streamGenLock.Lock()
	defer login.streamGenLock.Unlock()
	if login.streamGenerator != nil {
		return login.streamGenerator, nil
	}
	provider, ok := login.Bridge.Matrix.(streamGeneratorProvider)
	if !ok {
		return nil, fmt.Errorf("matrix connector doesn't support streams")
	}
	gen, err := provider.GetOrCreateStreamGenerator(ctx, &mautrix.StreamGeneratorOptions{
		AuthorizeSubscriber: login.authorizeStreamSubscriber,
	})
	if err != nil {
		return nil, err
	}
	login.streamGenerator = gen
	return gen, nil
}

func (login *UserLogin) authorizeStreamSubscriber(ctx context.Context, req *mautrix.StreamSubscribeRequest) bool {
	user, err := login.Bridge.GetUserByMXID(ctx, req.UserID)
	if err != nil {
		login.Log.Err(err).Stringer("sender", req.UserID).Msg("Failed to load stream subscriber user")
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
			Msg("Failed to load stream subscriber membership")
		return false
	}
	return member != nil && member.Membership == event.MembershipJoin
}
