// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

type Handler[MetaType any] struct {
	Func func(ce *Event[MetaType])

	// Name is the primary name of the command. It must be lowercase.
	Name string
	// Aliases are alternative names for the command. They must be lowercase.
	Aliases []string
	// Subcommands are subcommands of this command.
	Subcommands []*Handler[MetaType]

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
