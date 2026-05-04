// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package provisionutil

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type RespImagePackSavedToRoom struct {
	EventID  id.EventID `json:"event_id"`
	RoomID   id.RoomID  `json:"room_id"`
	StateKey string     `json:"state_key"`
}

func ImportImagePack(ctx context.Context, login *bridgev2.UserLogin, packURL string, saveToRoom bool) (any, error) {
	var spaceRoom id.RoomID
	if saveToRoom {
		var err error
		spaceRoom, err = login.GetSpaceRoom(ctx)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to get space room for user")
			return nil, bridgev2.RespError(mautrix.MUnknown.WithMessage("Failed to get space room for user"))
		} else if spaceRoom == "" {
			return nil, bridgev2.RespError(mautrix.MNotFound.WithMessage("Can't import image pack to space when personal filtering spaces are disabled"))
		}
	}
	api, ok := login.Client.(bridgev2.StickerImportingNetworkAPI)
	if !ok {
		return nil, bridgev2.RespError(mautrix.MUnrecognized.WithMessage("This bridge does not support importing image packs"))
	}
	resp, err := api.DownloadImagePack(ctx, packURL)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Str("pack_url", packURL).Msg("Failed to download image pack")
		return nil, err
	}
	if resp.Shortcode == "" && resp.Content.Metadata.BridgedPack != nil {
		resp.Shortcode = resp.Content.Metadata.BridgedPack.URL
	}
	evtContent := &event.Content{
		Parsed: resp.Content,
		Raw:    resp.Extra,
	}
	if saveToRoom {
		sendResp, err := login.Bridge.Bot.SendState(ctx, spaceRoom, event.StateImagePack, resp.Shortcode, evtContent, time.Now())
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to send image pack state event to space")
			return nil, fmt.Errorf("failed to send image pack state event to space: %w", err)
		}
		return &RespImagePackSavedToRoom{
			EventID:  sendResp.EventID,
			RoomID:   spaceRoom,
			StateKey: resp.Shortcode,
		}, nil
	}
	return evtContent, nil
}

func ListImagePacks(ctx context.Context, login *bridgev2.UserLogin) ([]*event.ImagePackMetadata, error) {
	api, ok := login.Client.(bridgev2.StickerImportingNetworkAPI)
	if !ok {
		return nil, bridgev2.RespError(mautrix.MUnrecognized.WithMessage("This bridge does not support importing image packs"))
	}
	return api.ListImagePacks(ctx)
}
