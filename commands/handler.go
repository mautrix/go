// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"strings"

	"maunium.net/go/mautrix/event"
)

type Handler[MetaType any] struct {
	// Func is the function that is called when the command is executed.
	Func func(ce *Event[MetaType])

	// Name is the primary name of the command. It must be lowercase.
	Name string
	// Aliases are alternative names for the command. They must be lowercase.
	Aliases []string
	// Description is a description of the command.
	Description *event.ExtensibleTextContainer
	// Subcommands are subcommands of this command.
	Subcommands []*Handler[MetaType]
	// PreFunc is a function that is called before checking subcommands.
	// It can be used to have parameters between subcommands (e.g. `!rooms <room ID> <command>`).
	// Event.ShiftArg will likely be useful for implementing such parameters.
	PreFunc func(ce *Event[MetaType])
	// Parameters are the parameters of the command. These are used to suggest auto-completions to clients,
	// but are not actually functional in any regard.
	Parameters []*event.MSC4391Parameter

	subcommandContainer *CommandContainer[MetaType]
}

func (h *Handler[MetaType]) initSubcommandContainer() {
	if len(h.Subcommands) > 0 {
		h.subcommandContainer = NewCommandContainer[MetaType]()
		h.subcommandContainer.Register(h.Subcommands...)
	} else {
		h.subcommandContainer = nil
	}
}

// MakeMSC4391Event creates a *event.MSC4391BotCommandEventContent representing this command handler.
func (h *Handler[MetaType]) MakeMSC4391Event() *event.MSC4391BotCommandEventContent {
	return &event.MSC4391BotCommandEventContent{
		Command:     h.Name,
		Aliases:     h.Aliases,
		Description: h.Description,
		Parameters:  h.Parameters,
	}
}

func MakeUnknownCommandHandler[MetaType any](prefix string) *Handler[MetaType] {
	return &Handler[MetaType]{
		Name: UnknownCommandName,
		Func: func(ce *Event[MetaType]) {
			if len(ce.ParentCommands) == 0 {
				ce.Reply("Unknown command `%s%s`", prefix, ce.Command)
			} else {
				ce.Reply("Unknown subcommand `%s%s %s`", prefix, strings.Join(ce.ParentCommands, " "), ce.Command)
			}
		},
	}
}
