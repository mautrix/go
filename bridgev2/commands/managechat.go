// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"time"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/event"
)

var CommandSyncChat = &FullHandler{
	Func: fnSyncChat,
	Name: "sync-portal",
	Help: HelpMeta{
		Section:     HelpSectionChats,
		Description: "Sync the current portal room",
	},
	RequiresPortal: true,
	RequiresLogin:  true,
}

func fnSyncChat(ce *Event) {
	login, _, err := ce.Portal.FindPreferredLogin(ce.Ctx, ce.User, false)
	if err != nil {
		ce.Log.Err(err).Msg("Failed to find login for sync")
		ce.Reply("Failed to find login: %v", err)
		return
	} else if login == nil {
		ce.Reply("No login found for sync")
		return
	}
	info, err := login.Client.GetChatInfo(ce.Ctx, ce.Portal)
	if err != nil {
		ce.Log.Err(err).Msg("Failed to get chat info for sync")
		ce.Reply("Failed to get chat info: %v", err)
		return
	}
	ce.Portal.UpdateInfo(ce.Ctx, info, login, nil, time.Time{})
	ce.React("✅️")
}

var CommandMute = &FullHandler{
	Func:    fnMute,
	Name:    "mute",
	Aliases: []string{"unmute"},
	Help: HelpMeta{
		Section:     HelpSectionChats,
		Description: "Mute or unmute a chat on the remote network",
		Args:        "[duration]",
	},
	RequiresPortal: true,
	RequiresLogin:  true,
	NetworkAPI:     NetworkAPIImplements[bridgev2.MuteHandlingNetworkAPI],
}

func fnMute(ce *Event) {
	_, api, _ := getClientForStartingChat[bridgev2.MuteHandlingNetworkAPI](ce, "muting chats")
	var mutedUntil int64
	if ce.Command == "mute" {
		mutedUntil = -1
		if len(ce.Args) > 0 {
			duration, err := time.ParseDuration(ce.Args[0])
			if err != nil {
				ce.Reply("Invalid duration: %v", err)
				return
			}
			mutedUntil = time.Now().Add(duration).UnixMilli()
		}
	}
	err := api.HandleMute(ce.Ctx, &bridgev2.MatrixMute{
		MatrixEventBase: bridgev2.MatrixEventBase[*event.BeeperMuteEventContent]{
			Content: &event.BeeperMuteEventContent{MutedUntil: mutedUntil},
			Portal:  ce.Portal,
		},
	})
	if err != nil {
		ce.Reply("Failed to %s chat: %v", ce.Command, err)
	} else {
		ce.React("✅️")
	}
}
