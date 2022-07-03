// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

var CommandHelp = &FullHandler{
	Func: func(ce *Event) {
		ce.Reply(FormatHelp(ce))
	},
	Name: "help",
	Help: HelpMeta{
		Section:     HelpSectionGeneral,
		Description: "Show this help message.",
	},
}

var CommandVersion = &FullHandler{
	Func: func(ce *Event) {
		ce.Reply("[%s](%s) %s (%s)", ce.Bridge.Name, ce.Bridge.URL, ce.Bridge.LinkifiedVersion, ce.Bridge.BuildTime)
	},
	Name: "version",
	Help: HelpMeta{
		Section:     HelpSectionGeneral,
		Description: "Get the bridge version.",
	},
}

var CommandCancel = &FullHandler{
	Func: func(ce *Event) {
		state := ce.User.GetCommandState()

		if state != nil {
			action, ok := state["action"].(string)
			if !ok {
				action = "Unknown action"
			}
			ce.User.SetCommandState(nil)
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
