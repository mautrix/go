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

var CommandSetManagementRoom = &FullHandler{
	Func: func(ce *Event) {
		if ce.User.ManagementRoom == ce.RoomID {
			ce.Reply("This room is already your management room")
			return
		} else if ce.Portal != nil {
			ce.Reply("This is a portal room: you can't set this as your management room")
			return
		}
		members, err := ce.Bridge.Matrix.GetMembers(ce.Ctx, ce.RoomID)
		if err != nil {
			ce.Log.Err(err).Msg("Failed to get room members to check if room can be a management room")
			ce.Reply("Failed to get room members")
			return
		}
		_, hasBot := members[ce.Bot.GetMXID()]
		if !hasBot {
			// This reply will probably fail, but whatever
			ce.Reply("The bridge bot must be in the room to set it as your management room")
			return
		} else if len(members) != 2 {
			ce.Reply("Your management room must not have any members other than you and the bridge bot")
			return
		}
		ce.User.ManagementRoom = ce.RoomID
		err = ce.User.Save(ce.Ctx)
		if err != nil {
			ce.Log.Err(err).Msg("Failed to save management room")
			ce.Reply("Failed to save management room")
		} else {
			ce.Reply("Management room updated")
		}
	},
	Name: "set-management-room",
	Help: HelpMeta{
		Section:     HelpSectionGeneral,
		Description: "Mark this room as your management room",
	},
}
