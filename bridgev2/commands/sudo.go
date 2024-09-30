// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"strings"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

var CommandSudo = &FullHandler{
	Func:    fnSudo,
	Name:    "sudo",
	Aliases: []string{"doas", "do-as", "runas", "run-as"},
	Help: HelpMeta{
		Section:     HelpSectionAdmin,
		Description: "Run a command as a different user.",
		Args:        "[--create] <_user ID_> <_command_> [_args..._]",
	},
	RequiresAdmin: true,
}

func fnSudo(ce *Event) {
	forceNonexistentUser := len(ce.Args) > 0 && strings.ToLower(ce.Args[0]) == "--create"
	if forceNonexistentUser {
		ce.Args = ce.Args[1:]
	}
	if len(ce.Args) < 2 {
		ce.Reply("Usage: `$cmdprefix sudo [--create] <user ID> <command> [args...]`")
		return
	}
	targetUserID := id.UserID(ce.Args[0])
	if _, _, err := targetUserID.Parse(); err != nil || len(targetUserID) > id.UserIDMaxLength {
		ce.Reply("Invalid user ID `%s`", targetUserID)
		return
	}
	var targetUser *bridgev2.User
	var err error
	if forceNonexistentUser {
		targetUser, err = ce.Bridge.GetUserByMXID(ce.Ctx, targetUserID)
	} else {
		targetUser, err = ce.Bridge.GetExistingUserByMXID(ce.Ctx, targetUserID)
	}
	if err != nil {
		ce.Log.Err(err).Msg("Failed to get user from database")
		ce.Reply("Failed to get user")
		return
	} else if targetUser == nil {
		ce.Reply("User not found. Use `--create` if you want to run commands as a user who has never used the bridge.")
		return
	}
	ce.User = targetUser
	origArgs := ce.Args[1:]
	ce.Command = strings.ToLower(ce.Args[1])
	ce.Args = ce.Args[2:]
	ce.RawArgs = strings.Join(ce.Args, " ")
	ce.Processor.handleCommand(ce.Ctx, ce, strings.Join(origArgs, " "), origArgs)
}

var CommandDoIn = &FullHandler{
	Func:    fnDoIn,
	Name:    "doin",
	Aliases: []string{"do-in", "runin", "run-in"},
	Help: HelpMeta{
		Section:     HelpSectionAdmin,
		Description: "Run a command in a different room.",
		Args:        "<_room ID_> <_command_> [_args..._]",
	},
}

func fnDoIn(ce *Event) {
	if len(ce.Args) < 2 {
		ce.Reply("Usage: `$cmdprefix doin <room ID> <command> [args...]`")
		return
	}
	targetRoomID := id.RoomID(ce.Args[0])
	if !ce.User.Permissions.Admin {
		memberInfo, err := ce.Bridge.Matrix.GetMemberInfo(ce.Ctx, targetRoomID, ce.User.MXID)
		if err != nil {
			ce.Log.Err(err).Msg("Failed to check if user is in doin target room")
			ce.Reply("Failed to check if you're in the target room")
			return
		} else if memberInfo == nil || memberInfo.Membership != event.MembershipJoin {
			ce.Reply("You must be in the target room to run commands there")
			return
		}
	}
	ce.RoomID = targetRoomID
	var err error
	ce.Portal, err = ce.Bridge.GetPortalByMXID(ce.Ctx, targetRoomID)
	if err != nil {
		ce.Log.Err(err).Msg("Failed to get target portal")
		ce.Reply("Failed to get portal")
		return
	}
	origArgs := ce.Args[1:]
	ce.Command = strings.ToLower(ce.Args[1])
	ce.Args = ce.Args[2:]
	ce.RawArgs = strings.Join(ce.Args, " ")
	ce.Processor.handleCommand(ce.Ctx, ce, strings.Join(origArgs, " "), origArgs)
}
