// Copyright (c) 2024 Tulir Asokan
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
	"maunium.net/go/mautrix/id"
)

func (ul *UserLogin) GetSpaceRoom(ctx context.Context) (id.RoomID, error) {
	ul.spaceCreateLock.Lock()
	defer ul.spaceCreateLock.Unlock()
	if ul.SpaceRoom != "" {
		return ul.SpaceRoom, nil
	}
	netName := ul.Bridge.Network.GetName()
	var err error
	req := &mautrix.ReqCreateRoom{
		Visibility: "private",
		Name:       fmt.Sprintf("%s (%s)", netName.DisplayName, ul.Metadata.RemoteName),
		Topic:      fmt.Sprintf("Your %s bridged chats - %s", netName.DisplayName, ul.Metadata.RemoteName),
		InitialState: []*event.Event{{
			Type: event.StateRoomAvatar,
			Content: event.Content{
				Parsed: &event.RoomAvatarEventContent{
					URL: netName.NetworkIcon,
				},
			},
		}},
		CreationContent: map[string]any{
			"type": event.RoomTypeSpace,
		},
		PowerLevelOverride: &event.PowerLevelsEventContent{
			Users: map[id.UserID]int{
				ul.Bridge.Bot.GetMXID(): 9001,
				ul.UserMXID:             50,
			},
		},
	}
	ul.SpaceRoom, err = ul.Bridge.Bot.CreateRoom(ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to create space room: %w", err)
	}
	ul.User.DoublePuppet(ctx).EnsureJoined(ctx, ul.SpaceRoom)
	err = ul.Save(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to save space room ID: %w", err)
	}
	return ul.SpaceRoom, nil
}
