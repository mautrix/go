// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"context"
	"runtime/debug"
	"strings"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
)

// Processor implements boilerplate code for splitting messages into a command and arguments,
// and finding the appropriate handler for the command.
type Processor[MetaType any] struct {
	*CommandContainer[MetaType]

	Client       *mautrix.Client
	LogArgs      bool
	PreValidator PreValidator[MetaType]
	Meta         MetaType

	ReactionCommandPrefix string
}

// UnknownCommandName is the name of the fallback handler which is used if no other handler is found.
// If even the unknown command handler is not found, the command is ignored.
const UnknownCommandName = "__unknown-command__"

func NewProcessor[MetaType any](cli *mautrix.Client) *Processor[MetaType] {
	proc := &Processor[MetaType]{
		CommandContainer: NewCommandContainer[MetaType](),
		Client:           cli,
		PreValidator:     ValidatePrefixSubstring[MetaType]("!"),
	}
	proc.Register(MakeUnknownCommandHandler[MetaType]("!"))
	return proc
}

func (proc *Processor[MetaType]) Process(ctx context.Context, evt *event.Event) {
	log := zerolog.Ctx(ctx).With().
		Stringer("sender", evt.Sender).
		Stringer("room_id", evt.RoomID).
		Stringer("event_id", evt.ID).
		Logger()
	defer func() {
		panicErr := recover()
		if panicErr != nil {
			logEvt := log.Error().
				Bytes(zerolog.ErrorStackFieldName, debug.Stack())
			if realErr, ok := panicErr.(error); ok {
				logEvt = logEvt.Err(realErr)
			} else {
				logEvt = logEvt.Any(zerolog.ErrorFieldName, panicErr)
			}
			logEvt.Msg("Panic in command handler")
			_, err := proc.Client.SendReaction(ctx, evt.RoomID, evt.ID, "💥")
			if err != nil {
				log.Err(err).Msg("Failed to send reaction after panic")
			}
		}
	}()
	var parsed *Event[MetaType]
	switch evt.Type {
	case event.EventReaction:
		parsed = proc.ParseReaction(ctx, evt)
	case event.EventMessage:
		parsed = ParseEvent[MetaType](ctx, evt)
	}
	if parsed == nil || !proc.PreValidator.Validate(parsed) {
		return
	}
	parsed.Proc = proc
	parsed.Meta = proc.Meta
	parsed.Ctx = ctx

	handler := proc.GetHandler(parsed.Command)
	if handler == nil {
		return
	}
	parsed.Handler = handler
	if handler.PreFunc != nil {
		handler.PreFunc(parsed)
	}
	handlerChain := zerolog.Arr()
	handlerChain.Str(handler.Name)
	for handler.subcommandContainer != nil && len(parsed.Args) > 0 {
		subHandler := handler.subcommandContainer.GetHandler(strings.ToLower(parsed.Args[0]))
		if subHandler != nil {
			parsed.ParentCommands = append(parsed.ParentCommands, parsed.Command)
			parsed.ParentHandlers = append(parsed.ParentHandlers, handler)
			handler = subHandler
			handlerChain.Str(subHandler.Name)
			parsed.Command = strings.ToLower(parsed.ShiftArg())
			parsed.Handler = subHandler
			if subHandler.PreFunc != nil {
				subHandler.PreFunc(parsed)
			}
		} else {
			break
		}
	}

	logWith := log.With().
		Str("command", parsed.Command).
		Array("handler", handlerChain)
	if len(parsed.ParentCommands) > 0 {
		logWith = logWith.Strs("parent_commands", parsed.ParentCommands)
	}
	if proc.LogArgs {
		logWith = logWith.Strs("args", parsed.Args)
	}
	log = logWith.Logger()
	parsed.Ctx = log.WithContext(ctx)
	parsed.Log = &log

	log.Debug().Msg("Processing command")
	handler.Func(parsed)
}
