// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func (ul *UserLogin) MarkInPortal(ctx context.Context, portal *Portal) {
	if ul.inPortalCache.Has(portal.PortalKey) {
		return
	}
	userPortal, err := ul.Bridge.DB.UserPortal.GetOrCreate(ctx, ul.UserLogin, portal.PortalKey)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to ensure user portal row exists")
		return
	}
	ul.inPortalCache.Add(portal.PortalKey)
	if ul.Bridge.Config.PersonalFilteringSpaces && (userPortal.InSpace == nil || !*userPortal.InSpace) && portal.MXID != "" {
		go ul.tryAddPortalToSpace(ctx, portal, userPortal.CopyWithoutValues())
	}
}

func (ul *UserLogin) tryAddPortalToSpace(ctx context.Context, portal *Portal, userPortal *database.UserPortal) {
	err := ul.AddPortalToSpace(ctx, portal, userPortal)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to add portal to space")
	}
}

func (ul *UserLogin) AddPortalToSpace(ctx context.Context, portal *Portal, userPortal *database.UserPortal) error {
	if portal.MXID == "" {
		return nil
	}
	spaceRoom, err := ul.GetSpaceRoom(ctx)
	if err != nil {
		return fmt.Errorf("failed to get space room: %w", err)
	} else if spaceRoom == "" {
		return nil
	}
	_, err = ul.Bridge.Bot.SendState(ctx, spaceRoom, event.StateSpaceChild, portal.MXID.String(), &event.Content{
		Parsed: &event.SpaceChildEventContent{
			Via: []string{ul.Bridge.Matrix.ServerName()},
		},
	}, time.Now())
	if err != nil {
		return fmt.Errorf("failed to add portal to space: %w", err)
	}
	inSpace := true
	userPortal.InSpace = &inSpace
	err = ul.Bridge.DB.UserPortal.Put(ctx, userPortal)
	if err != nil {
		return fmt.Errorf("failed to save user portal row: %w", err)
	}
	zerolog.Ctx(ctx).Debug().Stringer("space_room_id", spaceRoom).Msg("Added portal to space")
	return nil
}

func (ul *UserLogin) GetSpaceRoom(ctx context.Context) (id.RoomID, error) {
	if !ul.Bridge.Config.PersonalFilteringSpaces {
		return ul.SpaceRoom, nil
	}
	ul.spaceCreateLock.Lock()
	defer ul.spaceCreateLock.Unlock()
	if ul.SpaceRoom != "" {
		return ul.SpaceRoom, nil
	}
	netName := ul.Bridge.Network.GetName()
	var err error
	autoJoin := ul.Bridge.Matrix.GetCapabilities().AutoJoinInvites
	doublePuppet := ul.User.DoublePuppet(ctx)
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
		Invite: []id.UserID{ul.UserMXID},
	}
	if autoJoin {
		req.BeeperInitialMembers = []id.UserID{ul.UserMXID}
		// TODO remove this after initial_members is supported in hungryserv
		req.BeeperAutoJoinInvites = true
	}
	ul.SpaceRoom, err = ul.Bridge.Bot.CreateRoom(ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to create space room: %w", err)
	}
	if !autoJoin && doublePuppet != nil {
		err = doublePuppet.EnsureJoined(ctx, ul.SpaceRoom)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to auto-join created space room with double puppet")
		}
	}
	err = ul.Save(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to save space room ID: %w", err)
	}
	return ul.SpaceRoom, nil
}
