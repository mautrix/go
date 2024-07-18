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
	"maunium.net/go/mautrix/format"
)

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
			status := WrapErrorInStatus(errors.New("you don't have permission to send messages")).WithIsCertain(true).WithSendNotice(false).WithErrorAsMessage()
			br.Matrix.SendMessageStatus(ctx, &status, StatusEventInfoFromEvent(evt))
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
	} else {
		status := WrapErrorInStatus(ErrNoPortal)
		br.Matrix.SendMessageStatus(ctx, &status, StatusEventInfoFromEvent(evt))
	}
}

func (br *Bridge) handleBotInvite(ctx context.Context, evt *event.Event, sender *User) {
	log := zerolog.Ctx(ctx)
	if !sender.Permissions.Commands {
		_, err := br.Bot.SendState(ctx, evt.RoomID, event.StateMember, br.Bot.GetMXID().String(), &event.Content{
			Parsed: &event.MemberEventContent{
				Membership: event.MembershipLeave,
				Reason:     "You don't have permission to send commands to this bridge",
			},
		}, time.Time{})
		if err != nil {
			log.Err(err).Msg("Failed to reject invite from user with no permission")
		} else {
			log.Debug().Msg("Rejected invite from user with no permission")
		}
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

func (br *Bridge) QueueRemoteEvent(login *UserLogin, evt RemoteEvent) {
	log := login.Log
	ctx := log.WithContext(context.TODO())
	portal, err := br.GetPortalByKey(ctx, evt.GetPortalKey())
	if err != nil {
		log.Err(err).Object("portal_id", evt.GetPortalKey()).
			Msg("Failed to get portal to handle remote event")
		return
	}
	// TODO put this in a better place, and maybe cache to avoid constant db queries
	login.MarkInPortal(ctx, portal)
	portal.queueEvent(ctx, &portalRemoteEvent{
		evt:    evt,
		source: login,
	})
}
