// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/id"
)

func (br *Bridge) handleBotInvite(ctx context.Context, evt *event.Event, sender *User) {
	log := zerolog.Ctx(ctx)
	// These invites should already be rejected in QueueMatrixEvent
	if !sender.Permissions.Commands {
		log.Warn().Msg("Received bot invite from user without permission to send commands")
		return
	}
	err := br.Bot.EnsureJoined(ctx, evt.RoomID)
	if err != nil {
		log.Err(err).Msg("Failed to accept invite to room")
		return
	}
	log.Debug().Msg("Accepted invite to room as bot")
	members, err := br.Matrix.GetMembers(ctx, evt.RoomID)
	if err != nil {
		log.Err(err).Msg("Failed to get members of room after accepting invite")
	}
	if len(members) == 2 {
		var message string
		if sender.ManagementRoom == "" {
			message = fmt.Sprintf("Hello, I'm a %s bridge bot.\n\nUse `help` for help or `login` to log in.\n\nThis room has been marked as your management room.", br.Network.GetName().DisplayName)
			sender.ManagementRoom = evt.RoomID
			err = br.DB.User.Update(ctx, sender.User)
			if err != nil {
				log.Err(err).Msg("Failed to update user's management room in database")
			}
		} else {
			message = fmt.Sprintf("Hello, I'm a %s bridge bot.\n\nUse `%s help` for help.", br.Network.GetName().DisplayName, br.Config.CommandPrefix)
		}
		_, err = br.Bot.SendMessage(ctx, evt.RoomID, event.EventMessage, &event.Content{
			Parsed: format.RenderMarkdown(message, true, false),
		}, nil)
		if err != nil {
			log.Err(err).Msg("Failed to send welcome message to room")
		}
	}
}

func sendNotice(ctx context.Context, evt *event.Event, intent MatrixAPI, message string, args ...any) {
	if len(args) > 0 {
		message = fmt.Sprintf(message, args...)
	}
	content := format.RenderMarkdown(message, true, false)
	content.MsgType = event.MsgNotice
	resp, err := intent.SendMessage(ctx, evt.RoomID, event.EventMessage, &event.Content{Parsed: content}, nil)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Stringer("room_id", evt.RoomID).
			Stringer("inviter_id", evt.Sender).
			Stringer("invitee_id", intent.GetMXID()).
			Str("notice_text", message).
			Msg("Failed to send notice")
	} else {
		zerolog.Ctx(ctx).Debug().
			Stringer("notice_event_id", resp.EventID).
			Stringer("room_id", evt.RoomID).
			Stringer("inviter_id", evt.Sender).
			Stringer("invitee_id", intent.GetMXID()).
			Str("notice_text", message).
			Msg("Sent notice")
	}
}

func sendErrorAndLeave(ctx context.Context, evt *event.Event, intent MatrixAPI, message string, args ...any) {
	sendNotice(ctx, evt, intent, message, args...)
	rejectInvite(ctx, evt, intent, "")
}

func (br *Bridge) handleGhostDMInvite(ctx context.Context, evt *event.Event, sender *User) {
	ghostID, _ := br.Matrix.ParseGhostMXID(id.UserID(evt.GetStateKey()))
	validator, ok := br.Network.(IdentifierValidatingNetwork)
	if ghostID == "" || (ok && !validator.ValidateUserID(ghostID)) {
		rejectInvite(ctx, evt, br.Matrix.GhostIntent(ghostID), "Malformed user ID")
		return
	}
	log := zerolog.Ctx(ctx).With().
		Str("invitee_network_id", string(ghostID)).
		Stringer("room_id", evt.RoomID).
		Logger()
	// TODO sort in preference order
	logins := sender.GetUserLogins()
	if len(logins) == 0 {
		rejectInvite(ctx, evt, br.Matrix.GhostIntent(ghostID), "You're not logged in")
		return
	}
	_, ok = logins[0].Client.(IdentifierResolvingNetworkAPI)
	if !ok {
		rejectInvite(ctx, evt, br.Matrix.GhostIntent(ghostID), "This bridge does not support starting chats")
		return
	}
	invitedGhost, err := br.GetGhostByID(ctx, ghostID)
	if err != nil {
		log.Err(err).Msg("Failed to get invited ghost")
		return
	}
	err = invitedGhost.Intent.EnsureJoined(ctx, evt.RoomID)
	if err != nil {
		log.Err(err).Msg("Failed to accept invite to room")
		return
	}
	var resp *CreateChatResponse
	var sourceLogin *UserLogin
	// TODO this should somehow lock incoming event processing to avoid race conditions where a new portal room is created
	//      between ResolveIdentifier returning and the portal MXID being updated.
	for _, login := range logins {
		api, ok := login.Client.(IdentifierResolvingNetworkAPI)
		if !ok {
			continue
		}
		var resolveResp *ResolveIdentifierResponse
		ghostAPI, ok := login.Client.(GhostDMCreatingNetworkAPI)
		if ok {
			resp, err = ghostAPI.CreateChatWithGhost(ctx, invitedGhost)
		} else {
			resolveResp, err = api.ResolveIdentifier(ctx, string(ghostID), true)
			if resolveResp != nil {
				resp = resolveResp.Chat
			}
		}
		if errors.Is(err, ErrResolveIdentifierTryNext) {
			log.Debug().Err(err).Str("login_id", string(login.ID)).Msg("Failed to resolve identifier, trying next login")
			continue
		} else if err != nil {
			log.Err(err).Msg("Failed to resolve identifier")
			sendErrorAndLeave(ctx, evt, invitedGhost.Intent, "Failed to create chat")
			return
		} else {
			sourceLogin = login
			break
		}
	}
	if resp == nil {
		log.Warn().Msg("No login could resolve the identifier")
		sendErrorAndLeave(ctx, evt, br.Matrix.GhostIntent(ghostID), "Failed to create chat via any login")
		return
	}
	portal := resp.Portal
	if portal == nil {
		portal, err = br.GetPortalByKey(ctx, resp.PortalKey)
		if err != nil {
			log.Err(err).Msg("Failed to get portal by key")
			sendErrorAndLeave(ctx, evt, br.Matrix.GhostIntent(ghostID), "Failed to create portal entry")
			return
		}
	}
	err = invitedGhost.Intent.EnsureInvited(ctx, evt.RoomID, br.Bot.GetMXID())
	if err != nil {
		log.Err(err).Msg("Failed to ensure bot is invited to room")
		sendErrorAndLeave(ctx, evt, invitedGhost.Intent, "Failed to invite bridge bot")
		return
	}
	err = br.Bot.EnsureJoined(ctx, evt.RoomID)
	if err != nil {
		log.Err(err).Msg("Failed to ensure bot is joined to room")
		sendErrorAndLeave(ctx, evt, invitedGhost.Intent, "Failed to join with bridge bot")
		return
	}

	didSetPortal := portal.setMXIDToExistingRoom(ctx, evt.RoomID)
	if didSetPortal {
		message := "Private chat portal created"
		err = br.givePowerToBot(ctx, evt.RoomID, invitedGhost.Intent)
		hasWarning := false
		if err != nil {
			log.Warn().Err(err).Msg("Failed to give power to bot in new DM")
			message += "\n\nWarning: failed to promote bot"
			hasWarning = true
		}
		if resp.PortalInfo != nil {
			portal.UpdateInfo(ctx, resp.PortalInfo, sourceLogin, nil, time.Time{})
		} else {
			portal.UpdateCapabilities(ctx, sourceLogin, true)
			portal.UpdateBridgeInfo(ctx)
		}
		// TODO this might become unnecessary if UpdateInfo starts taking care of it
		_, err = br.Bot.SendState(ctx, portal.MXID, event.StateElementFunctionalMembers, "", &event.Content{
			Parsed: &event.ElementFunctionalMembersContent{
				ServiceMembers: []id.UserID{br.Bot.GetMXID()},
			},
		}, time.Time{})
		if err != nil {
			log.Warn().Err(err).Msg("Failed to set service members in room")
			if !hasWarning {
				message += "\n\nWarning: failed to set service members"
				hasWarning = true
			}
		}
		mx, ok := br.Matrix.(MatrixConnectorWithPostRoomBridgeHandling)
		if ok {
			err = mx.HandleNewlyBridgedRoom(ctx, evt.RoomID)
			if err != nil {
				if hasWarning {
					message += fmt.Sprintf(", %s", err.Error())
				} else {
					message += fmt.Sprintf("\n\nWarning: %s", err.Error())
				}
			}
		}
		sendNotice(ctx, evt, invitedGhost.Intent, message)
	} else {
		// TODO ensure user is invited even if PortalInfo wasn't provided?
		sendErrorAndLeave(ctx, evt, invitedGhost.Intent, "You already have a direct chat with me at [%s](%s)", portal.MXID, portal.MXID.URI(br.Matrix.ServerName()).MatrixToURL())
		rejectInvite(ctx, evt, br.Bot, "")
	}
}

func (br *Bridge) givePowerToBot(ctx context.Context, roomID id.RoomID, userWithPower MatrixAPI) error {
	powers, err := br.Matrix.GetPowerLevels(ctx, roomID)
	if err != nil {
		return fmt.Errorf("failed to get power levels: %w", err)
	}
	userLevel := powers.GetUserLevel(userWithPower.GetMXID())
	if powers.EnsureUserLevelAs(userWithPower.GetMXID(), br.Bot.GetMXID(), userLevel) {
		if userLevel > powers.UsersDefault {
			powers.SetUserLevel(userWithPower.GetMXID(), userLevel-1)
		}
		_, err = userWithPower.SendState(ctx, roomID, event.StatePowerLevels, "", &event.Content{
			Parsed: powers,
		}, time.Time{})
		if err != nil {
			return fmt.Errorf("failed to give power to bot: %w", err)
		}
	}
	return nil
}

func (portal *Portal) setMXIDToExistingRoom(ctx context.Context, roomID id.RoomID) bool {
	portal.roomCreateLock.Lock()
	defer portal.roomCreateLock.Unlock()
	if portal.MXID != "" {
		return false
	}
	portal.MXID = roomID
	portal.updateLogger()
	portal.Bridge.cacheLock.Lock()
	portal.Bridge.portalsByMXID[portal.MXID] = portal
	portal.Bridge.cacheLock.Unlock()
	err := portal.Save(ctx)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to save portal after updating mxid")
	}
	return true
}
