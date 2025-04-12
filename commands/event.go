// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
)

// Event contains the data of a single command event.
// It also provides some helper methods for responding to the command.
type Event[MetaType any] struct {
	*event.Event
	// RawInput is the entire message before splitting into command and arguments.
	RawInput string
	// Command is the lowercased first word of the message.
	Command string
	// Args are the rest of the message split by whitespace ([strings.Fields]).
	Args []string
	// RawArgs is the same as args, but without the splitting by whitespace.
	RawArgs string

	Ctx     context.Context
	Proc    *Processor[MetaType]
	Handler *Handler[MetaType]
	Meta    MetaType
}

var IDHTMLParser = &format.HTMLParser{
	PillConverter: func(displayname, mxid, eventID string, ctx format.Context) string {
		if len(mxid) == 0 {
			return displayname
		}
		if eventID != "" {
			return fmt.Sprintf("https://matrix.to/#/%s/%s", mxid, eventID)
		}
		return mxid
	},
	ItalicConverter: func(s string, c format.Context) string {
		return fmt.Sprintf("*%s*", s)
	},
	Newline: "\n",
}

// ParseEvent parses a message into a command event struct.
func ParseEvent[MetaType any](ctx context.Context, evt *event.Event) *Event[MetaType] {
	content := evt.Content.Parsed.(*event.MessageEventContent)
	text := content.Body
	if content.Format == event.FormatHTML {
		text = IDHTMLParser.Parse(content.FormattedBody, format.NewContext(ctx))
	}
	parts := strings.Fields(text)
	return &Event[MetaType]{
		Event:    evt,
		RawInput: text,
		Command:  strings.ToLower(parts[0]),
		Args:     parts[1:],
		RawArgs:  strings.TrimLeft(strings.TrimPrefix(text, parts[0]), " "),
		Ctx:      ctx,
	}
}

type ReplyOpts struct {
	AllowHTML     bool
	AllowMarkdown bool
	Reply         bool
	Thread        bool
	SendAsText    bool
}

func (evt *Event[MetaType]) Reply(msg string, args ...any) {
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	evt.Respond(msg, ReplyOpts{AllowMarkdown: true, Reply: true})
}

func (evt *Event[MetaType]) Respond(msg string, opts ReplyOpts) {
	content := format.RenderMarkdown(msg, opts.AllowMarkdown, opts.AllowHTML)
	if opts.Thread {
		content.SetThread(evt.Event)
	}
	if opts.Reply {
		content.SetReply(evt.Event)
	}
	if !opts.SendAsText {
		content.MsgType = event.MsgNotice
	}
	_, err := evt.Proc.Client.SendMessageEvent(evt.Ctx, evt.RoomID, event.EventMessage, content)
	if err != nil {
		zerolog.Ctx(evt.Ctx).Err(err).Msg("Failed to send reply")
	}
}

func (evt *Event[MetaType]) React(emoji string) {
	_, err := evt.Proc.Client.SendReaction(evt.Ctx, evt.RoomID, evt.ID, emoji)
	if err != nil {
		zerolog.Ctx(evt.Ctx).Err(err).Msg("Failed to send reaction")
	}
}

func (evt *Event[MetaType]) Redact() {
	_, err := evt.Proc.Client.RedactEvent(evt.Ctx, evt.RoomID, evt.ID)
	if err != nil {
		zerolog.Ctx(evt.Ctx).Err(err).Msg("Failed to redact command")
	}
}

func (evt *Event[MetaType]) MarkRead() {
	err := evt.Proc.Client.MarkRead(evt.Ctx, evt.RoomID, evt.ID)
	if err != nil {
		zerolog.Ctx(evt.Ctx).Err(err).Msg("Failed to send read receipt")
	}
}
