// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package provisionutil

import (
	"context"

	"github.com/rs/zerolog"
	"go.mau.fi/util/ptr"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type RespCreateGroup struct {
	ID     networkid.PortalID `json:"id"`
	MXID   id.RoomID          `json:"mxid"`
	Portal *bridgev2.Portal   `json:"-"`

	FailedParticipants map[networkid.UserID]*bridgev2.CreateChatFailedParticipant `json:"failed_participants,omitempty"`
}

func CreateGroup(ctx context.Context, login *bridgev2.UserLogin, params *bridgev2.GroupCreateParams) (*RespCreateGroup, error) {
	api, ok := login.Client.(bridgev2.GroupCreatingNetworkAPI)
	if !ok {
		return nil, bridgev2.RespError(mautrix.MUnrecognized.WithMessage("This bridge does not support creating groups"))
	}
	caps := login.Bridge.Network.GetCapabilities()
	typeSpec, validType := caps.Provisioning.GroupCreation[params.Type]
	if !validType {
		return nil, bridgev2.RespError(mautrix.MUnrecognized.WithMessage("Unrecognized group type %s", params.Type))
	}
	if len(params.Participants) < typeSpec.Participants.MinLength {
		return nil, bridgev2.RespError(mautrix.MInvalidParam.WithMessage("Must have at least %d members", typeSpec.Participants.MinLength))
	} else if typeSpec.Participants.MaxLength > 0 && len(params.Participants) > typeSpec.Participants.MaxLength {
		return nil, bridgev2.RespError(mautrix.MInvalidParam.WithMessage("Must have at most %d members", typeSpec.Participants.MaxLength))
	}
	userIDValidatingNetwork, uidValOK := login.Bridge.Network.(bridgev2.IdentifierValidatingNetwork)
	for i, participant := range params.Participants {
		parsedParticipant, ok := login.Bridge.Matrix.ParseGhostMXID(id.UserID(participant))
		if ok {
			participant = parsedParticipant
			params.Participants[i] = participant
		}
		if !typeSpec.Participants.SkipIdentifierValidation {
			if uidValOK && !userIDValidatingNetwork.ValidateUserID(participant) {
				return nil, bridgev2.RespError(mautrix.MInvalidParam.WithMessage("User ID %q is not valid on this network", participant))
			}
		}
		if api.IsThisUser(ctx, participant) {
			return nil, bridgev2.RespError(mautrix.MInvalidParam.WithMessage("You can't include yourself in the participants list", participant))
		}
	}
	if (params.Name == nil || params.Name.Name == "") && typeSpec.Name.Required {
		return nil, bridgev2.RespError(mautrix.MInvalidParam.WithMessage("Name is required"))
	} else if nameLen := len(ptr.Val(params.Name).Name); nameLen > 0 && nameLen < typeSpec.Name.MinLength {
		return nil, bridgev2.RespError(mautrix.MInvalidParam.WithMessage("Name must be at least %d characters", typeSpec.Name.MinLength))
	} else if typeSpec.Name.MaxLength > 0 && nameLen > typeSpec.Name.MaxLength {
		return nil, bridgev2.RespError(mautrix.MInvalidParam.WithMessage("Name must be at most %d characters", typeSpec.Name.MaxLength))
	}
	if (params.Avatar == nil || params.Avatar.URL == "") && typeSpec.Avatar.Required {
		return nil, bridgev2.RespError(mautrix.MInvalidParam.WithMessage("Avatar is required"))
	}
	if (params.Topic == nil || params.Topic.Topic == "") && typeSpec.Topic.Required {
		return nil, bridgev2.RespError(mautrix.MInvalidParam.WithMessage("Topic is required"))
	} else if topicLen := len(ptr.Val(params.Topic).Topic); topicLen > 0 && topicLen < typeSpec.Topic.MinLength {
		return nil, bridgev2.RespError(mautrix.MInvalidParam.WithMessage("Topic must be at least %d characters", typeSpec.Topic.MinLength))
	} else if typeSpec.Topic.MaxLength > 0 && topicLen > typeSpec.Topic.MaxLength {
		return nil, bridgev2.RespError(mautrix.MInvalidParam.WithMessage("Topic must be at most %d characters", typeSpec.Topic.MaxLength))
	}
	if (params.Disappear == nil || params.Disappear.Timer.Duration == 0) && typeSpec.Disappear.Required {
		return nil, bridgev2.RespError(mautrix.MInvalidParam.WithMessage("Disappearing timer is required"))
	} else if !typeSpec.Disappear.DisappearSettings.Supports(params.Disappear) {
		return nil, bridgev2.RespError(mautrix.MInvalidParam.WithMessage("Unsupported value for disappearing timer"))
	}
	if params.Username == "" && typeSpec.Username.Required {
		return nil, bridgev2.RespError(mautrix.MInvalidParam.WithMessage("Username is required"))
	} else if len(params.Username) > 0 && len(params.Username) < typeSpec.Username.MinLength {
		return nil, bridgev2.RespError(mautrix.MInvalidParam.WithMessage("Username must be at least %d characters", typeSpec.Username.MinLength))
	} else if typeSpec.Username.MaxLength > 0 && len(params.Username) > typeSpec.Username.MaxLength {
		return nil, bridgev2.RespError(mautrix.MInvalidParam.WithMessage("Username must be at most %d characters", typeSpec.Username.MaxLength))
	}
	if params.Parent == nil && typeSpec.Parent.Required {
		return nil, bridgev2.RespError(mautrix.MInvalidParam.WithMessage("Parent is required"))
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
	for key, fp := range resp.FailedParticipants {
		if fp.InviteEventType == "" {
			fp.InviteEventType = event.EventMessage.Type
		}
		if fp.UserMXID == "" {
			ghost, err := login.Bridge.GetGhostByID(ctx, key)
			if err != nil {
				zerolog.Ctx(ctx).Err(err).Msg("Failed to get ghost for failed participant")
			} else if ghost != nil {
				fp.UserMXID = ghost.Intent.GetMXID()
			}
		}
		if fp.DMRoomMXID == "" {
			portal, err := login.Bridge.GetDMPortal(ctx, login.ID, key)
			if err != nil {
				zerolog.Ctx(ctx).Err(err).Msg("Failed to get DM portal for failed participant")
			} else if portal != nil {
				fp.DMRoomMXID = portal.MXID
			}
		}
	}
	return &RespCreateGroup{
		ID:     resp.Portal.ID,
		MXID:   resp.Portal.MXID,
		Portal: resp.Portal,

		FailedParticipants: resp.FailedParticipants,
	}, nil
}
