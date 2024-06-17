// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"strings"

	"maunium.net/go/mautrix/bridgev2/networkid"
)

var CommandRegisterPush = &FullHandler{
	Func: func(ce *CommandEvent) {
		if len(ce.Args) < 3 {
			ce.Reply("Usage: `$cmdprefix debug-register-push <login ID> <push type> <push token>`\n\nYour logins:\n\n%s", ce.User.GetFormattedUserLogins())
			return
		}
		pushType := PushTypeFromString(ce.Args[1])
		if pushType == PushTypeUnknown {
			ce.Reply("Unknown push type `%s`. Allowed types: `web`, `apns`, `fcm`", ce.Args[1])
			return
		}
		login := ce.Bridge.GetCachedUserLoginByID(networkid.UserLoginID(ce.Args[0]))
		if login == nil || login.UserMXID != ce.User.MXID {
			ce.Reply("Login `%s` not found", ce.Args[0])
			return
		}
		pushable, ok := login.Client.(PushableNetworkAPI)
		if !ok {
			ce.Reply("This network connector does not support push registration")
			return
		}
		pushToken := strings.Join(ce.Args[2:], " ")
		if pushToken == "null" {
			pushToken = ""
		}
		err := pushable.RegisterPushNotifications(ce.Ctx, pushType, pushToken)
		if err != nil {
			ce.Reply("Failed to register pusher: %v", err)
			return
		}
		if pushToken == "" {
			ce.Reply("Pusher de-registered successfully")
		} else {
			ce.Reply("Pusher registered successfully")
		}
	},
	Name: "debug-register-push",
	Help: HelpMeta{
		Section:     HelpSectionAdmin,
		Description: "Register a pusher",
		Args:        "<_login ID_> <_push type_> <_push token_>",
	},
	RequiresAdmin: true,
	RequiresLogin: true,
}
