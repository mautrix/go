// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import "maunium.net/go/mautrix/bridge"

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
		if ce.Bridge.DoublePuppet.CanAutoDoublePuppet(ce.User.GetMXID()) {
			ce.Reply("Attempting to refresh double puppeting...")
			err = ce.User.GetIGhost().SwitchCustomMXID("", ce.User.GetMXID())
			if err != nil {
				ce.Reply("Failed to refresh double puppeting: %v", err)
			} else {
				ce.Reply("Successfully refreshed double puppeting")
			}
		}
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
	RequiresLogin: true,
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
	RequiresNoAutoDoublePuppeting: true,
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

var CommandRefreshMatrix = &FullHandler{
	Func: fnRefreshMatrix,
	Name: "refresh-matrix",
	Help: HelpMeta{
		Section:     HelpSectionAuth,
		Description: "Refresh double puppeting with an access token managed by the bridge.",
	},
	RequiresLogin:                  true,
	RequiresRefreshableMatrixLogin: true,
}

func fnRefreshMatrix(ce *Event) {
	if !ce.Bridge.DoublePuppet.CanAutoDoublePuppet(ce.User.GetMXID()) {
		ce.Reply("This bridge instance has disabled automatic double puppeting for your Matrix server.")
		return
	}
	var err error
	puppet := ce.User.GetIDoublePuppet()
	if puppet != nil {
		intent := puppet.CustomIntent()
		if intent != nil && intent.SetAppServiceUserID {
			ce.Reply("There is no need to refresh your double puppet, as it is currently managed by the bridge.")
			return
		}
		puppet, ok := puppet.(bridge.RefreshableDoublePuppet)
		if !ok {
			ce.Reply("The bridge does not support refreshing your double puppet.")
			return
		}
		err = puppet.RefreshCustomMXID()
	} else {
		err = ce.User.GetIGhost().SwitchCustomMXID("", ce.User.GetMXID())
	}
	if err != nil {
		ce.Reply("Failed to refresh double puppeting: %v", err)
	} else {
		ce.Reply("Successfully refreshed double puppeting")
	}
}
