// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package provisionutil

import (
	"context"
	"errors"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/id"
)

type RespResolveIdentifier struct {
	ID          networkid.UserID    `json:"id"`
	Name        string              `json:"name,omitempty"`
	AvatarURL   id.ContentURIString `json:"avatar_url,omitempty"`
	Identifiers []string            `json:"identifiers,omitempty"`
	MXID        id.UserID           `json:"mxid,omitempty"`
	DMRoomID    id.RoomID           `json:"dm_room_mxid,omitempty"`

	Portal      *bridgev2.Portal `json:"-"`
	Ghost       *bridgev2.Ghost  `json:"-"`
	JustCreated bool             `json:"-"`
}

var ErrNoPortalKey = errors.New("network API didn't return portal key for createChat request")

func ResolveIdentifier(
	ctx context.Context,
	login *bridgev2.UserLogin,
	identifier string,
	createChat bool,
) (*RespResolveIdentifier, error) {
	api, ok := login.Client.(bridgev2.IdentifierResolvingNetworkAPI)
	if !ok {
		return nil, bridgev2.RespError(mautrix.MUnrecognized.WithMessage("This bridge does not support resolving identifiers"))
	}
	var resp *bridgev2.ResolveIdentifierResponse
	parsedUserID, ok := login.Bridge.Matrix.ParseGhostMXID(id.UserID(identifier))
	validator, vOK := login.Bridge.Network.(bridgev2.IdentifierValidatingNetwork)
	if ok && (!vOK || validator.ValidateUserID(parsedUserID)) {
		ghost, err := login.Bridge.GetGhostByID(ctx, parsedUserID)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to get ghost by ID")
			return nil, err
		}
		resp = &bridgev2.ResolveIdentifierResponse{
			Ghost:  ghost,
			UserID: parsedUserID,
		}
		gdcAPI, ok := api.(bridgev2.GhostDMCreatingNetworkAPI)
		if ok && createChat {
			resp.Chat, err = gdcAPI.CreateChatWithGhost(ctx, ghost)
			if err != nil {
				zerolog.Ctx(ctx).Err(err).Msg("Failed to create chat")
				return nil, err
			}
		} else if createChat || ghost.Name == "" {
			zerolog.Ctx(ctx).Debug().
				Bool("create_chat", createChat).
				Bool("has_name", ghost.Name != "").
				Msg("Falling back to resolving identifier")
			resp = nil
			identifier = string(parsedUserID)
		}
	}
	if resp == nil {
		var err error
		resp, err = api.ResolveIdentifier(ctx, identifier, createChat)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to resolve identifier")
			return nil, err
		} else if resp == nil {
			return nil, nil
		}
	}
	apiResp := &RespResolveIdentifier{
		ID:    resp.UserID,
		Ghost: resp.Ghost,
	}
	if resp.Ghost != nil {
		if resp.UserInfo != nil {
			resp.Ghost.UpdateInfo(ctx, resp.UserInfo)
		}
		apiResp.Name = resp.Ghost.Name
		apiResp.AvatarURL = resp.Ghost.AvatarMXC
		apiResp.Identifiers = resp.Ghost.Identifiers
		apiResp.MXID = resp.Ghost.Intent.GetMXID()
	} else if resp.UserInfo != nil && resp.UserInfo.Name != nil {
		apiResp.Name = *resp.UserInfo.Name
	}
	if resp.Chat != nil {
		if resp.Chat.PortalKey.IsEmpty() {
			return nil, ErrNoPortalKey
		}
		if resp.Chat.Portal == nil {
			var err error
			resp.Chat.Portal, err = login.Bridge.GetPortalByKey(ctx, resp.Chat.PortalKey)
			if err != nil {
				zerolog.Ctx(ctx).Err(err).Msg("Failed to get portal")
				return nil, bridgev2.RespError(mautrix.MUnknown.WithMessage("Failed to get portal"))
			}
		}
		if createChat && resp.Chat.Portal.MXID == "" {
			apiResp.JustCreated = true
			err := resp.Chat.Portal.CreateMatrixRoom(ctx, login, resp.Chat.PortalInfo)
			if err != nil {
				zerolog.Ctx(ctx).Err(err).Msg("Failed to create portal room")
				return nil, bridgev2.RespError(mautrix.MUnknown.WithMessage("Failed to create portal room"))
			}
		}
		apiResp.Portal = resp.Chat.Portal
		apiResp.DMRoomID = resp.Chat.Portal.MXID
	}
	return apiResp, nil
}
