// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"cmp"
	"slices"

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
		getDepth := func(portal *bridgev2.Portal) int {
			depth := 0
			for portal.Parent != nil {
				depth++
				portal = portal.Parent
			}
			return depth
		}
		// Sort portals so parents are last (to avoid errors caused by deleting parent portals before children)
		slices.SortFunc(portals, func(a, b *bridgev2.Portal) int {
			return cmp.Compare(getDepth(b), getDepth(a))
		})
		for _, portal := range portals {
			err = portal.Delete(ce.Ctx)
			if err != nil {
				ce.Reply("Failed to delete portal %s: %v", portal.MXID, err)
				continue
			}
			err = ce.Bot.DeleteRoom(ce.Ctx, portal.MXID, false)
			if err != nil {
				ce.Reply("Failed to clean up room %s: %v", portal.MXID, err)
			}
		}
	},
	Name: "delete-all-portals",
	Help: HelpMeta{
		Section:     HelpSectionAdmin,
		Description: "Delete all portals the bridge knows about",
	},
	RequiresAdmin: true,
}
