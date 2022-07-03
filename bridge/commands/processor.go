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
	ce := &Event{
		Bot:       proc.bridge.Bot,
		Bridge:    proc.bridge,
		Portal:    proc.bridge.Child.GetIPortal(roomID),
		Processor: proc,
		RoomID:    roomID,
		EventID:   eventID,
		User:      user,
		Command:   strings.ToLower(args[0]),
		Args:      args[1:],
		ReplyTo:   replyTo,
		Log:       proc.log,
	}
	proc.log.Debugfln("%s sent '%s' in %s", user.GetMXID(), message, roomID)

	realCommand, ok := proc.aliases[ce.Command]
	if !ok {
		realCommand = ce.Command
	}

	var handler MinimalHandler
	handler, ok = proc.handlers[realCommand]
	if !ok {
		if state := ce.User.GetCommandState(); state != nil {
			ce.Command = ""
			ce.Args = args
			handler, ok = state["next"].(MinimalHandler)
			if ok {
				ce.Handler = handler
				handler.Run(ce)
			} else {
				ce.Reply("Unknown command, use the `help` command for help.")
			}
		} else {
			ce.Reply("Unknown command, use the `help` command for help.")
		}
	} else {
		ce.Log = ce.Log.Sub(realCommand)
		ce.Handler = handler
		handler.Run(ce)
	}
}
