// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"strings"
)

type Handler[MetaType any] struct {
	// Func is the function that is called when the command is executed.
	Func func(ce *Event[MetaType])

	// Name is the primary name of the command. It must be lowercase.
	Name string
	// Aliases are alternative names for the command. They must be lowercase.
	Aliases []string
	// Subcommands are subcommands of this command.
	Subcommands []*Handler[MetaType]
	// PreFunc is a function that is called before checking subcommands.
	// It can be used to have parameters between subcommands (e.g. `!rooms <room ID> <command>`).
	// Event.ShiftArg will likely be useful for implementing such parameters.
	PreFunc func(ce *Event[MetaType])

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
