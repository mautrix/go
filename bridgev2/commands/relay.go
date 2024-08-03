// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"golang.org/x/exp/slices"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"
)

var fakeEvtSetRelay = event.Type{Type: "fi.mau.bridge.set_relay", Class: event.StateEventType}

var CommandSetRelay = &FullHandler{
	Func: fnSetRelay,
	Name: "set-relay",
	Help: HelpMeta{
		Section:     HelpSectionAuth,
		Description: "Use your account to relay messages sent by users who haven't logged in",
		Args:        "[_login ID_]",
	},
	RequiresPortal: true,
}

func fnSetRelay(ce *Event) {
	if !ce.Bridge.Config.Relay.Enabled {
		ce.Reply("This bridge does not allow relay mode")
		return
	} else if !canManageRelay(ce) {
		ce.Reply("You don't have permission to manage the relay in this room")
		return
	}
	onlySetDefaultRelays := !ce.User.Permissions.Admin && ce.Bridge.Config.Relay.AdminOnly
	var relay *bridgev2.UserLogin
	if len(ce.Args) == 0 {
		relay = ce.User.GetDefaultLogin()
		isLoggedIn := relay != nil
		if onlySetDefaultRelays {
			relay = nil
		}
		if relay == nil {
			if len(ce.Bridge.Config.Relay.DefaultRelays) == 0 {
				ce.Reply("You're not logged in and there are no default relay users configured")
				return
			}
			logins, err := ce.Bridge.GetUserLoginsInPortal(ce.Ctx, ce.Portal.PortalKey)
			if err != nil {
				ce.Log.Err(err).Msg("Failed to get user logins in portal")
				ce.Reply("Failed to get logins in portal to find default relay")
				return
			}
		Outer:
			for _, loginID := range ce.Bridge.Config.Relay.DefaultRelays {
				for _, login := range logins {
					if login.ID == loginID {
						relay = login
						break Outer
					}
				}
			}
			if relay == nil {
				if isLoggedIn {
					ce.Reply("You're not allowed to use yourself as relay and none of the default relay users are in the chat")
				} else {
					ce.Reply("You're not logged in and none of the default relay users are in the chat")
				}
				return
			}
		}
	} else {
		relay = ce.Bridge.GetCachedUserLoginByID(networkid.UserLoginID(ce.Args[0]))
		if relay == nil {
			ce.Reply("User login with ID `%s` not found", ce.Args[0])
			return
		} else if slices.Contains(ce.Bridge.Config.Relay.DefaultRelays, relay.ID) {
			// All good
		} else if relay.UserMXID != ce.User.MXID && !ce.User.Permissions.Admin {
			ce.Reply("Only bridge admins can set another user's login as the relay")
			return
		} else if onlySetDefaultRelays {
			ce.Reply("You're not allowed to use yourself as relay")
			return
		}
	}
	err := ce.Portal.SetRelay(ce.Ctx, relay)
	if err != nil {
		ce.Log.Err(err).Msg("Failed to unset relay")
		ce.Reply("Failed to save relay settings")
	} else {
		ce.Reply(
			"Messages sent by users who haven't logged in will now be relayed through %s ([%s](%s)'s login)",
			relay.RemoteName,
			relay.UserMXID,
			// TODO this will need to stop linkifying if we ever allow UserLogins that aren't bound to a real user.
			relay.UserMXID.URI().MatrixToURL(),
		)
	}
}

var CommandUnsetRelay = &FullHandler{
	Func: fnUnsetRelay,
	Name: "unset-relay",
	Help: HelpMeta{
		Section:     HelpSectionAuth,
		Description: "Stop relaying messages sent by users who haven't logged in",
	},
	RequiresPortal: true,
}

func fnUnsetRelay(ce *Event) {
	if ce.Portal.Relay == nil {
		ce.Reply("This portal doesn't have a relay set.")
		return
	} else if !canManageRelay(ce) {
		ce.Reply("You don't have permission to manage the relay in this room")
		return
	}
	err := ce.Portal.SetRelay(ce.Ctx, nil)
	if err != nil {
		ce.Log.Err(err).Msg("Failed to unset relay")
		ce.Reply("Failed to save relay settings")
	} else {
		ce.Reply("Stopped relaying messages for users who haven't logged in")
	}
}

func canManageRelay(ce *Event) bool {
	return ce.User.Permissions.ManageRelay &&
		(ce.User.Permissions.Admin ||
			(ce.Portal.Relay != nil && ce.Portal.Relay.UserMXID == ce.User.MXID) ||
			hasRelayRoomPermissions(ce))
}

func hasRelayRoomPermissions(ce *Event) bool {
	levels, err := ce.Bridge.Matrix.GetPowerLevels(ce.Ctx, ce.RoomID)
	if err != nil {
		ce.Log.Err(err).Msg("Failed to check room power levels")
		return false
	}
	return levels.GetUserLevel(ce.User.MXID) >= levels.GetEventLevel(fakeEvtSetRelay)
}
