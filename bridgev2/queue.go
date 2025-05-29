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
	"strings"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func rejectInvite(ctx context.Context, evt *event.Event, intent MatrixAPI, reason string) {
	resp, err := intent.SendState(ctx, evt.RoomID, event.StateMember, intent.GetMXID().String(), &event.Content{
		Parsed: &event.MemberEventContent{
			Membership: event.MembershipLeave,
			Reason:     reason,
		},
	}, time.Time{})
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Stringer("room_id", evt.RoomID).
			Stringer("inviter_id", evt.Sender).
			Stringer("invitee_id", intent.GetMXID()).
			Str("reason", reason).
			Msg("Failed to reject invite")
	} else {
		zerolog.Ctx(ctx).Debug().
			Stringer("leave_event_id", resp.EventID).
			Stringer("room_id", evt.RoomID).
			Stringer("inviter_id", evt.Sender).
			Stringer("invitee_id", intent.GetMXID()).
			Str("reason", reason).
			Msg("Rejected invite")
	}
}

func (br *Bridge) rejectInviteOnNoPermission(ctx context.Context, evt *event.Event, permType string) bool {
	if evt.Type != event.StateMember || evt.Content.AsMember().Membership != event.MembershipInvite {
		return false
	}
	userID := id.UserID(evt.GetStateKey())
	parsed, isGhost := br.Matrix.ParseGhostMXID(userID)
	if userID != br.Bot.GetMXID() && !isGhost {
		return false
	}
	var intent MatrixAPI
	if userID == br.Bot.GetMXID() {
		intent = br.Bot
	} else {
		intent = br.Matrix.GhostIntent(parsed)
	}
	rejectInvite(ctx, evt, intent, "You don't have permission to "+permType+" this bridge")
	return true
}

func (br *Bridge) QueueMatrixEvent(ctx context.Context, evt *event.Event) {
	// TODO maybe HandleMatrixEvent would be more appropriate as this also handles bot invites and commands

	log := zerolog.Ctx(ctx)
	var sender *User
	if evt.Sender != "" {
		var err error
		sender, err = br.GetUserByMXID(ctx, evt.Sender)
		if err != nil {
			log.Err(err).Msg("Failed to get sender user for incoming Matrix event")
			status := WrapErrorInStatus(fmt.Errorf("%w: failed to get sender user: %w", ErrDatabaseError, err))
			br.Matrix.SendMessageStatus(ctx, &status, StatusEventInfoFromEvent(evt))
			return
		} else if sender == nil {
			log.Error().Msg("Couldn't get sender for incoming non-ephemeral Matrix event")
			status := WrapErrorInStatus(errors.New("sender not found for event")).WithIsCertain(true).WithErrorAsMessage()
			br.Matrix.SendMessageStatus(ctx, &status, StatusEventInfoFromEvent(evt))
			return
		} else if !sender.Permissions.SendEvents {
			if !br.rejectInviteOnNoPermission(ctx, evt, "interact with") {
				status := WrapErrorInStatus(errors.New("you don't have permission to send messages")).WithIsCertain(true).WithSendNotice(false).WithErrorAsMessage()
				br.Matrix.SendMessageStatus(ctx, &status, StatusEventInfoFromEvent(evt))
			}
			return
		} else if !sender.Permissions.Commands && br.rejectInviteOnNoPermission(ctx, evt, "send commands to") {
			return
		}
	} else if evt.Type.Class != event.EphemeralEventType {
		log.Error().Msg("Missing sender for incoming non-ephemeral Matrix event")
		status := WrapErrorInStatus(errors.New("sender not found for event")).WithIsCertain(true).WithErrorAsMessage()
		br.Matrix.SendMessageStatus(ctx, &status, StatusEventInfoFromEvent(evt))
		return
	}
	if evt.Type == event.EventMessage && sender != nil {
		msg := evt.Content.AsMessage()
		msg.RemoveReplyFallback()
		if strings.HasPrefix(msg.Body, br.Config.CommandPrefix) || evt.RoomID == sender.ManagementRoom {
			if !sender.Permissions.Commands {
				status := WrapErrorInStatus(errors.New("you don't have permission to use commands")).WithIsCertain(true).WithSendNotice(false).WithErrorAsMessage()
				br.Matrix.SendMessageStatus(ctx, &status, StatusEventInfoFromEvent(evt))
				return
			}
			br.Commands.Handle(
				ctx,
				evt.RoomID,
				evt.ID,
				sender,
				strings.TrimPrefix(msg.Body, br.Config.CommandPrefix+" "),
				msg.RelatesTo.GetReplyTo(),
			)
			return
		}
	}
	if evt.Type == event.StateMember && evt.GetStateKey() == br.Bot.GetMXID().String() && evt.Content.AsMember().Membership == event.MembershipInvite && sender != nil {
		br.handleBotInvite(ctx, evt, sender)
		return
	} else if sender != nil && evt.RoomID == sender.ManagementRoom {
		if evt.Type == event.StateMember && evt.Content.AsMember().Membership == event.MembershipLeave && (evt.GetStateKey() == br.Bot.GetMXID().String() || evt.GetStateKey() == sender.MXID.String()) {
			sender.ManagementRoom = ""
			err := br.DB.User.Update(ctx, sender.User)
			if err != nil {
				log.Err(err).Msg("Failed to clear user's management room in database")
			} else {
				log.Debug().Msg("Cleared user's management room due to leave event")
			}
		}
		return
	}
	portal, err := br.GetPortalByMXID(ctx, evt.RoomID)
	if err != nil {
		log.Err(err).Msg("Failed to get portal for incoming Matrix event")
		status := WrapErrorInStatus(fmt.Errorf("%w: failed to get portal: %w", ErrDatabaseError, err))
		br.Matrix.SendMessageStatus(ctx, &status, StatusEventInfoFromEvent(evt))
		return
	} else if portal != nil {
		portal.queueEvent(ctx, &portalMatrixEvent{
			evt:    evt,
			sender: sender,
		})
	} else if evt.Type == event.StateMember && br.IsGhostMXID(id.UserID(evt.GetStateKey())) && evt.Content.AsMember().Membership == event.MembershipInvite && evt.Content.AsMember().IsDirect {
		br.handleGhostDMInvite(ctx, evt, sender)
	} else {
		status := WrapErrorInStatus(ErrNoPortal)
		br.Matrix.SendMessageStatus(ctx, &status, StatusEventInfoFromEvent(evt))
	}
}

func (ul *UserLogin) QueueRemoteEvent(evt RemoteEvent) {
	ul.Bridge.QueueRemoteEvent(ul, evt)
}

func (br *Bridge) QueueRemoteEvent(login *UserLogin, evt RemoteEvent) {
	log := login.Log
	ctx := log.WithContext(br.BackgroundCtx)
	maybeUncertain, ok := evt.(RemoteEventWithUncertainPortalReceiver)
	isUncertain := ok && maybeUncertain.PortalReceiverIsUncertain()
	key := evt.GetPortalKey()
	var portal *Portal
	var err error
	if isUncertain && !br.Config.SplitPortals {
		portal, err = br.GetExistingPortalByKey(ctx, key)
	} else {
		portal, err = br.GetPortalByKey(ctx, key)
	}
	if err != nil {
		log.Err(err).Object("portal_key", key).Bool("uncertain_receiver", isUncertain).
			Msg("Failed to get portal to handle remote event")
		return
	} else if portal == nil {
		log.Warn().
			Stringer("event_type", evt.GetType()).
			Object("portal_key", key).
			Bool("uncertain_receiver", isUncertain).
			Msg("Portal not found to handle remote event")
		return
	}
	// TODO put this in a better place, and maybe cache to avoid constant db queries
	login.MarkInPortal(ctx, portal)
	portal.queueEvent(ctx, &portalRemoteEvent{
		evt:    evt,
		source: login,
	})
}
