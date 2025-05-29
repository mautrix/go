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
	"maunium.net/go/mautrix/id"
)

// Event contains the data of a single command event.
// It also provides some helper methods for responding to the command.
type Event[MetaType any] struct {
	*event.Event
	// RawInput is the entire message before splitting into command and arguments.
	RawInput string
	// ParentCommands is the chain of commands leading up to this command.
	// This is only set if the command is a subcommand.
	ParentCommands []string
	ParentHandlers []*Handler[MetaType]
	// Command is the lowercased first word of the message.
	Command string
	// Args are the rest of the message split by whitespace ([strings.Fields]).
	Args []string
	// RawArgs is the same as args, but without the splitting by whitespace.
	RawArgs string

	Ctx     context.Context
	Log     *zerolog.Logger
	Proc    *Processor[MetaType]
	Handler *Handler[MetaType]
	Meta    MetaType

	redactedBy id.EventID
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
	if content.MsgType == event.MsgNotice || content.RelatesTo.GetReplaceID() != "" {
		return nil
	}
	text := content.Body
	if content.Format == event.FormatHTML {
		text = IDHTMLParser.Parse(content.FormattedBody, format.NewContext(ctx))
	}
	if len(text) == 0 {
		return nil
	}
	return RawTextToEvent[MetaType](ctx, evt, text)
}

func RawTextToEvent[MetaType any](ctx context.Context, evt *event.Event, text string) *Event[MetaType] {
	parts := strings.Fields(text)
	if len(parts) == 0 {
		parts = []string{""}
	}
	return &Event[MetaType]{
		Event:    evt,
		RawInput: text,
		Command:  strings.ToLower(parts[0]),
		Args:     parts[1:],
		RawArgs:  strings.TrimLeft(strings.TrimPrefix(text, parts[0]), " "),
		Log:      zerolog.Ctx(ctx),
		Ctx:      ctx,
	}
}

type ReplyOpts struct {
	AllowHTML        bool
	AllowMarkdown    bool
	Reply            bool
	Thread           bool
	SendAsText       bool
	Edit             id.EventID
	OverrideMentions *event.Mentions
	Extra            map[string]any
}

func (evt *Event[MetaType]) Reply(msg string, args ...any) id.EventID {
	if len(args) > 0 {
		msg = fmt.Sprintf(msg, args...)
	}
	return evt.Respond(msg, ReplyOpts{AllowMarkdown: true, Reply: true})
}

func (evt *Event[MetaType]) Respond(msg string, opts ReplyOpts) id.EventID {
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
	if opts.Edit != "" {
		content.SetEdit(opts.Edit)
	}
	if opts.OverrideMentions != nil {
		content.Mentions = opts.OverrideMentions
	}
	var wrapped any = &content
	if opts.Extra != nil {
		wrapped = &event.Content{
			Parsed: &content,
			Raw:    opts.Extra,
		}
	}
	resp, err := evt.Proc.Client.SendMessageEvent(evt.Ctx, evt.RoomID, event.EventMessage, wrapped)
	if err != nil {
		zerolog.Ctx(evt.Ctx).Err(err).Msg("Failed to send reply")
		return ""
	}
	return resp.EventID
}

func (evt *Event[MetaType]) React(emoji string) id.EventID {
	resp, err := evt.Proc.Client.SendReaction(evt.Ctx, evt.RoomID, evt.ID, emoji)
	if err != nil {
		zerolog.Ctx(evt.Ctx).Err(err).Msg("Failed to send reaction")
		return ""
	}
	return resp.EventID
}

func (evt *Event[MetaType]) Redact() id.EventID {
	if evt.redactedBy != "" {
		return evt.redactedBy
	}
	resp, err := evt.Proc.Client.RedactEvent(evt.Ctx, evt.RoomID, evt.ID)
	if err != nil {
		zerolog.Ctx(evt.Ctx).Err(err).Msg("Failed to redact command")
		return ""
	}
	evt.redactedBy = resp.EventID
	return resp.EventID
}

func (evt *Event[MetaType]) MarkRead() {
	err := evt.Proc.Client.MarkRead(evt.Ctx, evt.RoomID, evt.ID)
	if err != nil {
		zerolog.Ctx(evt.Ctx).Err(err).Msg("Failed to send read receipt")
	}
}

// ShiftArg removes the first argument from the Args list and RawArgs data and returns it.
// RawInput will not be modified.
func (evt *Event[MetaType]) ShiftArg() string {
	if len(evt.Args) == 0 {
		return ""
	}
	firstArg := evt.Args[0]
	evt.RawArgs = strings.TrimLeft(strings.TrimPrefix(evt.RawArgs, evt.Args[0]), " ")
	evt.Args = evt.Args[1:]
	return firstArg
}

// UnshiftArg reverses ShiftArg by adding the given value to the beginning of the Args list and RawArgs data.
func (evt *Event[MetaType]) UnshiftArg(arg string) {
	evt.RawArgs = arg + " " + evt.RawArgs
	evt.Args = append([]string{arg}, evt.Args...)
}
