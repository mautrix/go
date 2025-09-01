// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package provisionutil

import (
	"context"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/id"
)

type RespCreateGroup struct {
	ID     networkid.PortalID `json:"id"`
	MXID   id.RoomID          `json:"mxid"`
	Portal *bridgev2.Portal   `json:"-"`
}

func CreateGroup(ctx context.Context, login *bridgev2.UserLogin, params *bridgev2.GroupCreateParams) (*RespCreateGroup, error) {
	api, ok := login.Client.(bridgev2.GroupCreatingNetworkAPI)
	if !ok {
		return nil, bridgev2.RespError(mautrix.MUnrecognized.WithMessage("This bridge does not support creating groups"))
	}
	caps := login.Bridge.Network.GetCapabilities()
	if _, validType := caps.Provisioning.GroupCreation[params.Type]; !validType {
		return nil, bridgev2.RespError(mautrix.MUnrecognized.WithMessage("Unrecognized group type %s", params.Type))
	}
	resp, err := api.CreateGroup(ctx, params)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to create group")
		return nil, err
	}
	if resp.PortalKey.IsEmpty() {
		return nil, ErrNoPortalKey
	}
	if resp.Portal == nil {
		resp.Portal, err = login.Bridge.GetPortalByKey(ctx, resp.PortalKey)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to get portal")
			return nil, bridgev2.RespError(mautrix.MUnknown.WithMessage("Failed to get portal"))
		}
	}
	if resp.Portal.MXID == "" {
		err = resp.Portal.CreateMatrixRoom(ctx, login, resp.PortalInfo)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to create portal room")
			return nil, bridgev2.RespError(mautrix.MUnknown.WithMessage("Failed to create portal room"))
		}
	}
	return &RespCreateGroup{
		ID:     resp.Portal.ID,
		MXID:   resp.Portal.MXID,
		Portal: resp.Portal,
	}, nil
}
