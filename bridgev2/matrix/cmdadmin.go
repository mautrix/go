// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"strconv"

	"maunium.net/go/mautrix/bridgev2/commands"
	"maunium.net/go/mautrix/id"
)

var CommandDiscardMegolmSession = &commands.FullHandler{
	Func: func(ce *commands.Event) {
		matrix := ce.Bridge.Matrix.(*Connector)
		if matrix.Crypto == nil {
			ce.Reply("This bridge instance doesn't have end-to-bridge encryption enabled")
		} else {
			matrix.Crypto.ResetSession(ce.Ctx, ce.RoomID)
			ce.Reply("Successfully reset Megolm session in this room. New decryption keys will be shared the next time a message is sent from the remote network.")
		}
	},
	Name:    "discard-megolm-session",
	Aliases: []string{"discard-session"},
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionAdmin,
		Description: "Discard the Megolm session in the room",
	},
	RequiresAdmin: true,
}

func fnSetPowerLevel(ce *commands.Event) {
	var level int
	var userID id.UserID
	var err error
	if len(ce.Args) == 1 {
		level, err = strconv.Atoi(ce.Args[0])
		if err != nil {
			ce.Reply("Invalid power level \"%s\"", ce.Args[0])
			return
		}
		userID = ce.User.MXID
	} else if len(ce.Args) == 2 {
		userID = id.UserID(ce.Args[0])
		_, _, err := userID.Parse()
		if err != nil {
			ce.Reply("Invalid user ID \"%s\"", ce.Args[0])
			return
		}
		level, err = strconv.Atoi(ce.Args[1])
		if err != nil {
			ce.Reply("Invalid power level \"%s\"", ce.Args[1])
			return
		}
	} else {
		ce.Reply("**Usage:** `set-pl [user] <level>`")
		return
	}
	_, err = ce.Bot.(*ASIntent).Matrix.SetPowerLevel(ce.Ctx, ce.RoomID, userID, level)
	if err != nil {
		ce.Reply("Failed to set power levels: %v", err)
	}
}

var CommandSetPowerLevel = &commands.FullHandler{
	Func:    fnSetPowerLevel,
	Name:    "set-pl",
	Aliases: []string{"set-power-level"},
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionAdmin,
		Description: "Change the power level in a portal room.",
		Args:        "[_user ID_] <_power level_>",
	},
	RequiresAdmin:  true,
	RequiresPortal: true,
}
