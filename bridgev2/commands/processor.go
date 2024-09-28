// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/bridgev2"

	"maunium.net/go/mautrix/bridge/status"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type Processor struct {
	bridge *bridgev2.Bridge
	log    *zerolog.Logger

	handlers map[string]CommandHandler
	aliases  map[string]string
}

// NewProcessor creates a Processor
func NewProcessor(bridge *bridgev2.Bridge) bridgev2.CommandProcessor {
	proc := &Processor{
		bridge: bridge,
		log:    &bridge.Log,

		handlers: make(map[string]CommandHandler),
		aliases:  make(map[string]string),
	}
	proc.AddHandlers(
		CommandHelp, CommandCancel,
		CommandRegisterPush, CommandDeletePortal, CommandDeleteAllPortals,
		CommandLogin, CommandListLogins, CommandLogout, CommandSetPreferredLogin,
		CommandSetRelay, CommandUnsetRelay,
		CommandResolveIdentifier, CommandStartChat, CommandSearch,
		CommandSudo, CommandDoIn,
	)
	return proc
}

func (proc *Processor) AddHandlers(handlers ...CommandHandler) {
	for _, handler := range handlers {
		proc.AddHandler(handler)
	}
}

func (proc *Processor) AddHandler(handler CommandHandler) {
	proc.handlers[handler.GetName()] = handler
	aliased, ok := handler.(AliasedCommandHandler)
	if ok {
		for _, alias := range aliased.GetAliases() {
			proc.aliases[alias] = handler.GetName()
		}
	}
}

// Handle handles messages to the bridge
func (proc *Processor) Handle(ctx context.Context, roomID id.RoomID, eventID id.EventID, user *bridgev2.User, message string, replyTo id.EventID) {
	ms := &bridgev2.MessageStatus{
		Step:   status.MsgStepCommand,
		Status: event.MessageStatusSuccess,
	}
	defer func() {
		statusInfo := &bridgev2.MessageStatusEventInfo{
			RoomID:    roomID,
			EventID:   eventID,
			EventType: event.EventMessage,
			Sender:    user.MXID,
		}
		err := recover()
		if err != nil {
			logEvt := zerolog.Ctx(ctx).Error().
				Bytes(zerolog.ErrorStackFieldName, debug.Stack())
			if realErr, ok := err.(error); ok {
				logEvt = logEvt.Err(realErr)
			} else {
				logEvt = logEvt.Any(zerolog.ErrorFieldName, err)
			}
			logEvt.Msg("Panic in Matrix command handler")
			ms.Status = event.MessageStatusFail
			ms.IsCertain = true
			if realErr, ok := err.(error); ok {
				ms.InternalError = realErr
			} else {
				ms.InternalError = fmt.Errorf("%v", err)
			}
			ms.ErrorAsMessage = true
		}
		proc.bridge.Matrix.SendMessageStatus(ctx, ms, statusInfo)
	}()
	args := strings.Fields(message)
	if len(args) == 0 {
		args = []string{"unknown-command"}
	}
	command := strings.ToLower(args[0])
	rawArgs := strings.TrimLeft(strings.TrimPrefix(message, command), " ")
	portal, err := proc.bridge.GetPortalByMXID(ctx, roomID)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to get portal")
		// :(
	}
	ce := &Event{
		Bot:        proc.bridge.Bot,
		Bridge:     proc.bridge,
		Portal:     portal,
		Processor:  proc,
		RoomID:     roomID,
		OrigRoomID: roomID,
		EventID:    eventID,
		User:       user,
		Command:    command,
		Args:       args[1:],
		RawArgs:    rawArgs,
		ReplyTo:    replyTo,
		Ctx:        ctx,

		MessageStatus: ms,
	}
	proc.handleCommand(ctx, ce, message, args)
}

func (proc *Processor) handleCommand(ctx context.Context, ce *Event, origMessage string, origArgs []string) {
	realCommand, ok := proc.aliases[ce.Command]
	if !ok {
		realCommand = ce.Command
	}

	var handler MinimalCommandHandler
	handler, ok = proc.handlers[realCommand]
	if !ok {
		state := LoadCommandState(ce.User)
		if state != nil && state.Next != nil {
			ce.Command = ""
			ce.RawArgs = origMessage
			ce.Args = origArgs
			ce.Handler = state.Next
			log := zerolog.Ctx(ctx).With().Str("action", state.Action).Logger()
			ce.Log = &log
			ce.Ctx = log.WithContext(ctx)
			log.Debug().Msg("Received reply to command state")
			state.Next.Run(ce)
		} else {
			zerolog.Ctx(ctx).Debug().Str("mx_command", ce.Command).Msg("Received unknown command")
			ce.Reply("Unknown command, use the `help` command for help.")
		}
	} else {
		log := zerolog.Ctx(ctx).With().Str("mx_command", ce.Command).Logger()
		ctx = log.WithContext(ctx)
		ce.Log = &log
		ce.Ctx = ctx
		log.Debug().Msg("Received command")
		ce.Handler = handler
		handler.Run(ce)
	}
}

func LoadCommandState(user *bridgev2.User) *CommandState {
	return (*CommandState)(atomic.LoadPointer(&user.CommandState))
}

func StoreCommandState(user *bridgev2.User, cs *CommandState) {
	atomic.StorePointer(&user.CommandState, unsafe.Pointer(cs))
}

func SwapCommandState(user *bridgev2.User, cs *CommandState) *CommandState {
	return (*CommandState)(atomic.SwapPointer(&user.CommandState, unsafe.Pointer(cs)))
}

var CommandCancel = &FullHandler{
	Func: func(ce *Event) {
		state := SwapCommandState(ce.User, nil)
		if state != nil {
			action := state.Action
			if action == "" {
				action = "Unknown action"
			}
			if state.Cancel != nil {
				state.Cancel()
			}
			ce.Reply("%s cancelled.", action)
		} else {
			ce.Reply("No ongoing command.")
		}
	},
	Name: "cancel",
	Help: HelpMeta{
		Section:     HelpSectionGeneral,
		Description: "Cancel an ongoing action.",
	},
}
