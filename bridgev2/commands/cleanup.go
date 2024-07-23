// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"maunium.net/go/mautrix/bridgev2"
)

var CommandDeletePortal = &FullHandler{
	Func: func(ce *Event) {
		// TODO clean up child portals?
		err := ce.Portal.Delete(ce.Ctx)
		if err != nil {
			ce.Reply("Failed to delete portal: %v", err)
			return
		}
		err = ce.Bot.DeleteRoom(ce.Ctx, ce.Portal.MXID, false)
		if err != nil {
			ce.Reply("Failed to clean up room: %v", err)
		}
		ce.MessageStatus.DisableMSS = true
	},
	Name: "delete-portal",
	Help: HelpMeta{
		Section:     HelpSectionAdmin,
		Description: "Delete the current portal room",
	},
	RequiresAdmin:  true,
	RequiresPortal: true,
}

var CommandDeleteAllPortals = &FullHandler{
	Func: func(ce *Event) {
		portals, err := ce.Bridge.GetAllPortals(ce.Ctx)
		if err != nil {
			ce.Reply("Failed to get portals: %v", err)
			return
		}
		bridgev2.DeleteManyPortals(ce.Ctx, portals, func(portal *bridgev2.Portal, delete bool, err error) {
			if !delete {
				ce.Reply("Failed to delete portal %s: %v", portal.MXID, err)
			} else {
				ce.Reply("Failed to clean up room %s: %v", portal.MXID, err)
			}
		})
	},
	Name: "delete-all-portals",
	Help: HelpMeta{
		Section:     HelpSectionAdmin,
		Description: "Delete all portals the bridge knows about",
	},
	RequiresAdmin: true,
}
