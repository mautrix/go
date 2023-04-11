// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"maunium.net/go/maulogger/v2"

	"maunium.net/go/mautrix"
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
	Handler   MinimalHandler
	RoomID    id.RoomID
	EventID   id.EventID
	User      bridge.User
	Command   string
	Args      []string
	RawArgs   string
	ReplyTo   id.EventID
	ZLog      *zerolog.Logger
	// Deprecated: switch to ZLog
	Log maulogger.Logger
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

// Reply sends a reply to command as notice, with optional string formatting and automatic $cmdprefix replacement.
func (ce *Event) Reply(msg string, args ...interface{}) {
	msg = strings.ReplaceAll(msg, "$cmdprefix ", ce.Bridge.Config.Bridge.GetCommandPrefix()+" ")
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
	_, err := ce.MainIntent().SendMessageEvent(ce.RoomID, event.EventMessage, content)
	if err != nil {
		ce.ZLog.Error().Err(err).Msgf("Failed to reply to command")
	}
}

// React sends a reaction to the command.
func (ce *Event) React(key string) {
	_, err := ce.MainIntent().SendReaction(ce.RoomID, ce.EventID, key)
	if err != nil {
		ce.ZLog.Error().Err(err).Msgf("Failed to react to command")
	}
}

// Redact redacts the command.
func (ce *Event) Redact(req ...mautrix.ReqRedact) {
	_, err := ce.MainIntent().RedactEvent(ce.RoomID, ce.EventID, req...)
	if err != nil {
		ce.ZLog.Error().Err(err).Msgf("Failed to redact command")
	}
}

// MarkRead marks the command event as read.
func (ce *Event) MarkRead() {
	err := ce.MainIntent().SendReceipt(ce.RoomID, ce.EventID, event.ReceiptTypeRead, nil)
	if err != nil {
		ce.ZLog.Error().Err(err).Msgf("Failed to mark command as read")
	}
}
