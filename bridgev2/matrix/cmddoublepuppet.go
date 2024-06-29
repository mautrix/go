// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"maunium.net/go/mautrix/bridgev2/commands"
)

var CommandLoginMatrix = &commands.FullHandler{
	Func: fnLoginMatrix,
	Name: "login-matrix",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionAuth,
		Description: "Enable double puppeting.",
		Args:        "<_access token_>",
	},
	RequiresLogin: true,
}

func fnLoginMatrix(ce *commands.Event) {
	if !ce.User.Permissions.DoublePuppet {
		ce.Reply("You don't have permission to manage double puppeting.")
		return
	}
	if len(ce.Args) == 0 {
		ce.Reply("**Usage:** `login-matrix <access token>`")
		return
	}
	err := ce.User.LoginDoublePuppet(ce.Ctx, ce.Args[0])
	if err != nil {
		ce.Reply("Failed to enable double puppeting: %v", err)
	} else {
		ce.Reply("Successfully switched puppets")
	}
}

var CommandPingMatrix = &commands.FullHandler{
	Func: fnPingMatrix,
	Name: "ping-matrix",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionAuth,
		Description: "Ping the Matrix server with the double puppet.",
	},
}

func fnPingMatrix(ce *commands.Event) {
	intent := ce.User.DoublePuppet(ce.Ctx)
	if intent == nil {
		ce.Reply("You don't have double puppeting enabled.")
		return
	}
	asIntent := intent.(*ASIntent)
	resp, err := asIntent.Matrix.Whoami(ce.Ctx)
	if err != nil {
		ce.Reply("Failed to validate Matrix login: %v", err)
	} else {
		if asIntent.Matrix.SetAppServiceUserID && resp.DeviceID == "" {
			ce.Reply("Confirmed valid access token for %s (appservice double puppeting)", resp.UserID)
		} else {
			ce.Reply("Confirmed valid access token for %s / %s", resp.UserID, resp.DeviceID)
		}
	}
}

var CommandLogoutMatrix = &commands.FullHandler{
	Func: fnLogoutMatrix,
	Name: "logout-matrix",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionAuth,
		Description: "Disable double puppeting.",
	},
	RequiresLogin: true,
}

func fnLogoutMatrix(ce *commands.Event) {
	if !ce.User.Permissions.DoublePuppet {
		ce.Reply("You don't have permission to manage double puppeting.")
		return
	}
	if ce.User.AccessToken == "" {
		ce.Reply("You don't have double puppeting enabled.")
		return
	}
	ce.User.LogoutDoublePuppet(ce.Ctx)
	ce.Reply("Successfully disabled double puppeting.")
}
