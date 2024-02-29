// Copyright (c) 2023 Tulir Asokan
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
	"maunium.net/go/maulogger/v2/maulogadapt"

	"github.com/element-hq/mautrix-go/bridge"
	"github.com/element-hq/mautrix-go/id"
)

type Processor struct {
	bridge *bridge.Bridge
	log    *zerolog.Logger

	handlers map[string]Handler
	aliases  map[string]string
}

// NewProcessor creates a Processor
func NewProcessor(bridge *bridge.Bridge) *Processor {
	proc := &Processor{
		bridge: bridge,
		log:    bridge.ZLog,

		handlers: make(map[string]Handler),
		aliases:  make(map[string]string),
	}
	proc.AddHandlers(
		CommandHelp, CommandVersion, CommandCancel,
		CommandLoginMatrix, CommandLogoutMatrix, CommandPingMatrix,
		CommandDiscardMegolmSession, CommandSetPowerLevel)
	return proc
}

func (proc *Processor) AddHandlers(handlers ...Handler) {
	for _, handler := range handlers {
		proc.AddHandler(handler)
	}
}

func (proc *Processor) AddHandler(handler Handler) {
	proc.handlers[handler.GetName()] = handler
	aliased, ok := handler.(AliasedHandler)
	if ok {
		for _, alias := range aliased.GetAliases() {
			proc.aliases[alias] = handler.GetName()
		}
	}
}

// Handle handles messages to the bridge
func (proc *Processor) Handle(ctx context.Context, roomID id.RoomID, eventID id.EventID, user bridge.User, message string, replyTo id.EventID) {
	defer func() {
		err := recover()
		if err != nil {
			zerolog.Ctx(ctx).Error().
				Str(zerolog.ErrorStackFieldName, string(debug.Stack())).
				Interface(zerolog.ErrorFieldName, err).
				Msg("Panic in Matrix command handler")
		}
	}()
	args := strings.Fields(message)
	if len(args) == 0 {
		args = []string{"unknown-command"}
	}
	command := strings.ToLower(args[0])
	rawArgs := strings.TrimLeft(strings.TrimPrefix(message, command), " ")
	log := zerolog.Ctx(ctx).With().Str("mx_command", command).Logger()
	ctx = log.WithContext(ctx)
	ce := &Event{
		Bot:       proc.bridge.Bot,
		Bridge:    proc.bridge,
		Portal:    proc.bridge.Child.GetIPortal(roomID),
		Processor: proc,
		RoomID:    roomID,
		EventID:   eventID,
		User:      user,
		Command:   command,
		Args:      args[1:],
		RawArgs:   rawArgs,
		ReplyTo:   replyTo,
		Ctx:       ctx,
		ZLog:      &log,
		Log:       maulogadapt.ZeroAsMau(&log),
	}
	log.Debug().Msg("Received command")

	realCommand, ok := proc.aliases[ce.Command]
	if !ok {
		realCommand = ce.Command
	}
	commandingUser, ok := ce.User.(CommandingUser)

	var handler MinimalHandler
	handler, ok = proc.handlers[realCommand]
	if !ok {
		var state *CommandState
		if commandingUser != nil {
			state = commandingUser.GetCommandState()
		}
		if state != nil && state.Next != nil {
			ce.Command = ""
			ce.Args = args
			ce.Handler = state.Next
			state.Next.Run(ce)
		} else {
			ce.Reply("Unknown command, use the `help` command for help.")
		}
	} else {
		ce.Handler = handler
		handler.Run(ce)
	}
}
