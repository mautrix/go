// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

var CommandHelp = &FullHandler{
	Func: func(ce *CommandEvent) {
		ce.Reply(FormatHelp(ce))
	},
	Name: "help",
	Help: HelpMeta{
		Section:     HelpSectionGeneral,
		Description: "Show this help message.",
	},
}

var CommandCancel = &FullHandler{
	Func: func(ce *CommandEvent) {
		state := ce.User.CommandState.Swap(nil)
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
