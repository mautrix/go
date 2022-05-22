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
