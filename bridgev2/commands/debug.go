// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"encoding/json"
	"strings"
	"time"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"
)

var CommandRegisterPush = &FullHandler{
	Func: func(ce *Event) {
		if len(ce.Args) < 3 {
			ce.Reply("Usage: `$cmdprefix debug-register-push <login ID> <push type> <push token>`\n\nYour logins:\n\n%s", ce.User.GetFormattedUserLogins())
			return
		}
		pushType := bridgev2.PushTypeFromString(ce.Args[1])
		if pushType == bridgev2.PushTypeUnknown {
			ce.Reply("Unknown push type `%s`. Allowed types: `web`, `apns`, `fcm`", ce.Args[1])
			return
		}
		login := ce.Bridge.GetCachedUserLoginByID(networkid.UserLoginID(ce.Args[0]))
		if login == nil || login.UserMXID != ce.User.MXID {
			ce.Reply("Login `%s` not found", ce.Args[0])
			return
		}
		pushable, ok := login.Client.(bridgev2.PushableNetworkAPI)
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
	NetworkAPI:    NetworkAPIImplements[bridgev2.PushableNetworkAPI],
}

var CommandSendAccountData = &FullHandler{
	Func: func(ce *Event) {
		if len(ce.Args) < 2 {
			ce.Reply("Usage: `$cmdprefix debug-account-data <type> <content>")
			return
		}
		var content event.Content
		evtType := event.Type{Type: ce.Args[0], Class: event.AccountDataEventType}
		ce.RawArgs = strings.TrimSpace(strings.Trim(ce.RawArgs, ce.Args[0]))
		err := json.Unmarshal([]byte(ce.RawArgs), &content)
		if err != nil {
			ce.Reply("Failed to parse JSON: %v", err)
			return
		}
		err = content.ParseRaw(evtType)
		if err != nil {
			ce.Reply("Failed to deserialize content: %v", err)
			return
		}
		res := ce.Bridge.QueueMatrixEvent(ce.Ctx, &event.Event{
			Sender:    ce.User.MXID,
			Type:      evtType,
			Timestamp: time.Now().UnixMilli(),
			RoomID:    ce.RoomID,
			Content:   content,
		})
		ce.Reply("Result: %+v", res)
	},
	Name: "debug-account-data",
	Help: HelpMeta{
		Section:     HelpSectionAdmin,
		Description: "Send a room account data event to the bridge",
		Args:        "<_type_> <_content_>",
	},
	RequiresAdmin:  true,
	RequiresPortal: true,
	RequiresLogin:  true,
}
