// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"fmt"

	"maunium.net/go/maulogger/v2"

	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/bridge"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/id"
)

// Event stores all data which might be used to handle commands
type Event struct {
	Bot       *appservice.IntentAPI
	Bridge    *bridge.Bridge
	Portal    bridge.Portal
	Processor *Processor
	Handler   Handler
	RoomID    id.RoomID
	EventID   id.EventID
	User      bridge.User
	Command   string
	Args      []string
	ReplyTo   id.EventID
	Log       maulogger.Logger
}

// MainIntent returns the intent to use when replying to the command.
//
// It prefers the bridge bot, but falls back to the other user in DMs if the bridge bot is not present.
func (ce *Event) MainIntent() *appservice.IntentAPI {
	intent := ce.Bot
	if ce.Portal != nil && ce.Portal.IsPrivateChat() && !ce.Portal.IsEncrypted() {
		intent = ce.Portal.MainIntent()
	}
	return intent
}

// Reply sends a reply to command as notice.
func (ce *Event) Reply(msg string, args ...interface{}) {
	content := format.RenderMarkdown(fmt.Sprintf(msg, args...), true, false)
	content.MsgType = event.MsgNotice
	_, err := ce.MainIntent().SendMessageEvent(ce.RoomID, event.EventMessage, content)
	if err != nil {
		ce.Processor.log.Warnfln("Failed to reply to command from %s: %v", ce.User.GetMXID(), err)
	}
}

// React sends a reaction to the command.
func (ce *Event) React(key string) {
	_, err := ce.MainIntent().SendReaction(ce.RoomID, ce.EventID, key)
	if err != nil {
		ce.Processor.log.Warnfln("Failed to react to command from %s: %v", ce.User.GetMXID(), err)
	}
}

// MarkRead marks the command event as read.
func (ce *Event) MarkRead() {
	err := ce.MainIntent().MarkRead(ce.RoomID, ce.EventID)
	if err != nil {
		ce.Processor.log.Warnfln("Failed to mark command from %s as read: %v", ce.User.GetMXID(), err)
	}
}
