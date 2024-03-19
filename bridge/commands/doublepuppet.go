// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

var CommandLoginMatrix = &FullHandler{
	Func: fnLoginMatrix,
	Name: "login-matrix",
	Help: HelpMeta{
		Section:     HelpSectionAuth,
		Description: "Enable double puppeting with an access token for your Matrix account.",
		Args:        "<_access token_>",
	},
	RequiresLogin:                 true,
	RequiresManualDoublePuppeting: true,
}

func fnLoginMatrix(ce *Event) {
	if len(ce.Args) == 0 {
		ce.Reply("**Usage:** `login-matrix <access token>`")
		return
	}
	puppet := ce.User.GetIDoublePuppet()
	if puppet == nil {
		puppet = ce.User.GetIGhost()
		if puppet == nil {
			ce.Reply("Didn't get a ghost :(")
			return
		}
	}
	err := puppet.SwitchCustomMXID(ce.Args[0], ce.User.GetMXID())
	if err != nil {
		ce.Reply("Failed to enable double puppeting: %v", err)
	} else {
		ce.Reply("Successfully switched puppet")
	}
}

var CommandPingMatrix = &FullHandler{
	Func: fnPingMatrix,
	Name: "ping-matrix",
	Help: HelpMeta{
		Section:     HelpSectionAuth,
		Description: "Ping the Matrix server with your double puppet.",
	},
	RequiresLogin:                 true,
	RequiresManualDoublePuppeting: true,
}

func fnPingMatrix(ce *Event) {
	puppet := ce.User.GetIDoublePuppet()
	if puppet == nil || puppet.CustomIntent() == nil {
		ce.Reply("You are not logged in with your Matrix account.")
		return
	}
	resp, err := puppet.CustomIntent().Whoami(ce.Ctx)
	if err != nil {
		ce.Reply("Failed to validate Matrix login: %v", err)
	} else if resp.DeviceID == "" {
		ce.Reply("Confirmed valid access token for %s", resp.UserID)
	} else {
		ce.Reply("Confirmed valid access token for %s / %s", resp.UserID, resp.DeviceID)
	}
}

var CommandLogoutMatrix = &FullHandler{
	Func: fnLogoutMatrix,
	Name: "logout-matrix",
	Help: HelpMeta{
		Section:     HelpSectionAuth,
		Description: "Disable double puppeting.",
	},
	RequiresLogin:                 true,
	RequiresManualDoublePuppeting: true,
}

func fnLogoutMatrix(ce *Event) {
	puppet := ce.User.GetIDoublePuppet()
	if puppet == nil || puppet.CustomIntent() == nil {
		ce.Reply("You don't have double puppeting enabled.")
		return
	}
	puppet.ClearCustomMXID()
	ce.Reply("Successfully disabled double puppeting.")
}
