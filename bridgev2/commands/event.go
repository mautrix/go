// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/bridgev2"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/id"
)

// Event stores all data which might be used to handle commands
type Event struct {
	Bot        bridgev2.MatrixAPI
	Bridge     *bridgev2.Bridge
	Portal     *bridgev2.Portal
	Processor  *Processor
	Handler    MinimalCommandHandler
	RoomID     id.RoomID
	OrigRoomID id.RoomID
	EventID    id.EventID
	User       *bridgev2.User
	Command    string
	Args       []string
	RawArgs    string
	ReplyTo    id.EventID
	Ctx        context.Context
	Log        *zerolog.Logger

	MessageStatus *bridgev2.MessageStatus
}

// Reply sends a reply to command as notice, with optional string formatting and automatic $cmdprefix replacement.
func (ce *Event) Reply(msg string, args ...any) {
	msg = strings.ReplaceAll(msg, "$cmdprefix ", ce.Bridge.Config.CommandPrefix+" ")
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	ce.ReplyAdvanced(msg, true, false)
}

// ReplyAdvanced sends a reply to command as notice. It allows using HTML and disabling markdown,
// but doesn't have built-in string formatting.
func (ce *Event) ReplyAdvanced(msg string, allowMarkdown, allowHTML bool) {
	content := format.RenderMarkdown(msg, allowMarkdown, allowHTML)
	content.MsgType = event.MsgNotice
	_, err := ce.Bot.SendMessage(ce.Ctx, ce.OrigRoomID, event.EventMessage, &event.Content{Parsed: &content}, nil)
	if err != nil {
		ce.Log.Err(err).Msg("Failed to reply to command")
	}
}

// React sends a reaction to the command.
func (ce *Event) React(key string) {
	_, err := ce.Bot.SendMessage(ce.Ctx, ce.OrigRoomID, event.EventReaction, &event.Content{
		Parsed: &event.ReactionEventContent{
			RelatesTo: event.RelatesTo{
				Type:    event.RelAnnotation,
				EventID: ce.EventID,
				Key:     key,
			},
		},
	}, nil)
	if err != nil {
		ce.Log.Err(err).Msg("Failed to react to command")
	}
}

// Redact redacts the command.
func (ce *Event) Redact(req ...mautrix.ReqRedact) {
	_, err := ce.Bot.SendMessage(ce.Ctx, ce.OrigRoomID, event.EventRedaction, &event.Content{
		Parsed: &event.RedactionEventContent{
			Redacts: ce.EventID,
		},
	}, nil)
	if err != nil {
		ce.Log.Err(err).Msg("Failed to redact command")
	}
}

// MarkRead marks the command event as read.
func (ce *Event) MarkRead() {
	err := ce.Bot.MarkRead(ce.Ctx, ce.RoomID, ce.EventID, time.Now())
	if err != nil {
		ce.Log.Err(err).Msg("Failed to mark command as read")
	}
}
