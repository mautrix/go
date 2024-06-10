// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/bridge/status"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type CommandProcessor struct {
	bridge *Bridge
	log    *zerolog.Logger

	handlers map[string]CommandHandler
	aliases  map[string]string
}

// NewProcessor creates a CommandProcessor
func NewProcessor(bridge *Bridge) *CommandProcessor {
	proc := &CommandProcessor{
		bridge: bridge,
		log:    &bridge.Log,

		handlers: make(map[string]CommandHandler),
		aliases:  make(map[string]string),
	}
	proc.AddHandlers(
		CommandHelp, CommandVersion, CommandCancel,
		CommandLogin, CommandLogout, CommandSetPreferredLogin,
	)
	return proc
}

func (proc *CommandProcessor) AddHandlers(handlers ...CommandHandler) {
	for _, handler := range handlers {
		proc.AddHandler(handler)
	}
}

func (proc *CommandProcessor) AddHandler(handler CommandHandler) {
	proc.handlers[handler.GetName()] = handler
	aliased, ok := handler.(AliasedCommandHandler)
	if ok {
		for _, alias := range aliased.GetAliases() {
			proc.aliases[alias] = handler.GetName()
		}
	}
}

// Handle handles messages to the bridge
func (proc *CommandProcessor) Handle(ctx context.Context, roomID id.RoomID, eventID id.EventID, user *User, message string, replyTo id.EventID) {
	defer func() {
		statusInfo := &MessageStatusEventInfo{
			RoomID:    roomID,
			EventID:   eventID,
			EventType: event.EventMessage,
			Sender:    user.MXID,
		}
		ms := MessageStatus{
			Step:   status.MsgStepCommand,
			Status: event.MessageStatusSuccess,
		}
		err := recover()
		if err != nil {
			zerolog.Ctx(ctx).Error().
				Bytes(zerolog.ErrorStackFieldName, debug.Stack()).
				Any(zerolog.ErrorFieldName, err).
				Msg("Panic in Matrix command handler")
			ms.Status = event.MessageStatusFail
			ms.IsCertain = true
			if realErr, ok := err.(error); ok {
				ms.InternalError = realErr
			} else {
				ms.InternalError = fmt.Errorf("%v", err)
			}
			ms.ErrorAsMessage = true
		}
		proc.bridge.Matrix.SendMessageStatus(ctx, &ms, statusInfo)
	}()
	args := strings.Fields(message)
	if len(args) == 0 {
		args = []string{"unknown-command"}
	}
	command := strings.ToLower(args[0])
	rawArgs := strings.TrimLeft(strings.TrimPrefix(message, command), " ")
	portal, err := proc.bridge.GetPortalByMXID(ctx, roomID)
	if err != nil {
		// :(
	}
	ce := &CommandEvent{
		Bot:       proc.bridge.Bot,
		Bridge:    proc.bridge,
		Portal:    portal,
		Processor: proc,
		RoomID:    roomID,
		EventID:   eventID,
		User:      user,
		Command:   command,
		Args:      args[1:],
		RawArgs:   rawArgs,
		ReplyTo:   replyTo,
		Ctx:       ctx,
	}

	realCommand, ok := proc.aliases[ce.Command]
	if !ok {
		realCommand = ce.Command
	}

	var handler MinimalCommandHandler
	handler, ok = proc.handlers[realCommand]
	if !ok {
		state := ce.User.CommandState.Load()
		if state != nil && state.Next != nil {
			ce.Command = ""
			ce.RawArgs = message
			ce.Args = args
			ce.Handler = state.Next
			log := zerolog.Ctx(ctx).With().Str("action", state.Action).Logger()
			ce.Log = &log
			ce.Ctx = log.WithContext(ctx)
			log.Debug().Msg("Received reply to command state")
			state.Next.Run(ce)
		} else {
			zerolog.Ctx(ctx).Debug().Str("mx_command", command).Msg("Received unknown command")
			ce.Reply("Unknown command, use the `help` command for help.")
		}
	} else {
		log := zerolog.Ctx(ctx).With().Str("mx_command", command).Logger()
		ctx = log.WithContext(ctx)
		ce.Log = &log
		ce.Ctx = ctx
		log.Debug().Msg("Received command")
		ce.Handler = handler
		handler.Run(ce)
	}
}
