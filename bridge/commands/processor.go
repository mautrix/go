// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"runtime/debug"
	"strings"

	"maunium.net/go/maulogger/v2"

	"maunium.net/go/mautrix/bridge"
	"maunium.net/go/mautrix/id"
)

type Processor struct {
	bridge *bridge.Bridge
	log    maulogger.Logger

	handlers map[string]Handler
	aliases  map[string]string
}

// NewProcessor creates a Processor
func NewProcessor(bridge *bridge.Bridge) *Processor {
	proc := &Processor{
		bridge: bridge,
		log:    bridge.Log.Sub("CommandProcessor"),

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
func (proc *Processor) Handle(roomID id.RoomID, eventID id.EventID, user bridge.User, message string, replyTo id.EventID) {
	defer func() {
		err := recover()
		if err != nil {
			proc.log.Errorfln("Panic handling command from %s: %v\n%s", user.GetMXID(), err, debug.Stack())
		}
	}()
	args := strings.Fields(message)
	if len(args) == 0 {
		args = []string{"unknown-command"}
	}
	command := strings.ToLower(args[0])
	rawArgs := strings.TrimLeft(strings.TrimPrefix(message, command), " ")
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
		Log:       proc.log,
	}
	proc.log.Debugfln("%s sent %q in %s", user.GetMXID(), message, roomID)

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
		ce.Log = ce.Log.Sub(realCommand)
		ce.Handler = handler
		handler.Run(ce)
	}
}
