// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/bridgeconfig"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
)

var CommandID = &FullHandler{
	Func: func(ce *Event) {
		var receiver string
		if ce.Portal.Receiver != "" {
			receiver = fmt.Sprintf(" (receiver: %s)", format.SafeMarkdownCode(ce.Portal.Receiver))
		}
		ce.Reply("This room is bridged to %s%s on %s", format.SafeMarkdownCode(ce.Portal.ID), receiver, ce.Bridge.Network.GetName().DisplayName)
	},
	Name: "id",
	Help: HelpMeta{
		Section:     HelpSectionChats,
		Description: "View the internal network ID of the current portal room",
	},
	RequiresPortal: true,
}

var CommandBridge = &FullHandler{
	Func: fnBridge,
	Name: "bridge",
	Help: HelpMeta{
		Section:     HelpSectionChats,
		Description: "Bridge an existing chat on the remote network to this Matrix room",
		Args:        "[login ID] <chat ID>",
	},
	RequiresEventLevel: event.StateBridge,
}

func fnBridge(ce *Event) {
	if len(ce.Args) == 0 || len(ce.Args) > 2 {
		ce.Reply("Usage: `$cmdprefix bridge [login ID] <chat ID>`")
		return
	} else if !canPlumb(ce) {
		ce.Reply("You don't have permission to bridge this room")
		return
	} else if ce.Portal != nil {
		ce.Reply("This room is already bridged")
		return
	}
	var allowOverwrite, ignorePermissions bool
	ce.Args = slices.DeleteFunc(ce.Args, func(s string) bool {
		switch strings.ToLower(s) {
		case "--overwrite":
			allowOverwrite = true
			return true
		case "--ignore-permissions":
			ignorePermissions = true
			return true
		default:
			return false
		}
	})
	if !ignorePermissions {
		pls, err := ce.Bridge.Matrix.GetPowerLevels(ce.Ctx, ce.RoomID)
		if err != nil {
			ce.Log.Err(err).Msg("Failed to get power levels for plumbing")
			ce.Reply("Failed to check power levels in room: %v", err)
			return
		} else if pls.GetUserLevel(ce.Bot.GetMXID()) < pls.GetEventLevel(event.StateBridge) {
			ce.Reply("I don't have sufficient permissions for `m.bridge` events. Adjust power levels or use the `--ignore-permissions` flag to ignore.")
			return
		}
	}
	portal, login, ok := getCreatePortalInput(ce, ce.Bridge.Config.Relay.AllowBridge)
	if !ok {
		return
	} else if portal.MXID != "" {
		// TODO check overwrite permissions
		canOverwrite := ce.User.Permissions.Admin || hasRoomPermissions(ce, portal.MXID, fakeEvtPlumb)
		if !canOverwrite {
			ce.Reply("That chat is already bridged to another room, and you don't have the permission to delete it.")
			return
		} else if !allowOverwrite {
			ce.Reply("That chat is already bridged to [%s](%s). Use `--overwrite` to delete the existing room.", portal.Name, portal.MXID.URI().MatrixToURL())
			return
		}
	}
	if info, err := login.Client.GetChatInfo(ce.Ctx, portal); err != nil {
		ce.Log.Err(err).Msg("Failed to get chat info for plumbing")
		ce.Reply("Failed to get chat info: %v", err)
	} else if info == nil {
		ce.Reply("Chat info not found")
	} else if err = portal.UpdateMatrixRoomID(ce.Ctx, ce.RoomID, bridgev2.UpdateMatrixRoomIDParams{
		FailIfMXIDSet:    !allowOverwrite,
		TombstoneOldRoom: true,
		DeleteOldRoom:    true,
		ChatInfo:         info,
		ChatInfoSource:   login,
	}); err != nil {
		ce.Log.Err(err).Msg("Failed to plumb room")
		ce.Reply("Failed to plumb room: %v", err)
	} else {
		var relaySuffix string
		if slices.Contains(ce.Bridge.Config.Relay.DefaultRelays, login.ID) {
			err = portal.SetRelay(ce.Ctx, login)
			if err != nil {
				ce.Log.Err(err).Msg("Failed to set relay for portal after plumbing")
				relaySuffix = fmt.Sprintf(", but failed to set %s as relay", format.SafeMarkdownCode(login.ID))
			} else {
				relaySuffix = fmt.Sprintf(" and set %s as relay", format.SafeMarkdownCode(login.ID))
			}
		}
		ce.Reply(
			"Successfully plumbed this room to %s on %s%s",
			format.SafeMarkdownCode(portal.ID),
			ce.Bridge.Network.GetName().DisplayName,
			relaySuffix,
		)
	}
}

var CommandUnbridge = &FullHandler{
	Func: func(ce *Event) {
		if !canPlumb(ce) {
			ce.Reply("You don't have permission to unbridge this portal")
			return
		}
		mxid := ce.Portal.MXID
		err := ce.Portal.RemoveMXID(ce.Ctx)
		if err != nil {
			ce.Reply("Failed to remove portal mxid: %v", err)
			return
		}
		err = ce.Bot.DeleteRoom(ce.Ctx, mxid, true)
		if err != nil {
			ce.Reply("Failed to clean up room: %v", err)
		}
		ce.MessageStatus.DisableMSS = true
	},
	Name: "unbridge",
	Help: HelpMeta{
		Section:     HelpSectionChats,
		Description: "Unbridge the current portal room",
	},
	RequiresPortal: true,
}

var CommandSyncChat = &FullHandler{
	Func: fnSyncChat,
	Name: "sync-portal",
	Help: HelpMeta{
		Section:     HelpSectionChats,
		Description: "Sync the current portal room",
	},
	RequiresPortal: true,
}

func fnSyncChat(ce *Event) {
	login, _, err := ce.Portal.FindPreferredLogin(ce.Ctx, ce.User, ce.Bridge.Config.Relay.AllowBridge)
	if err != nil {
		ce.Log.Err(err).Msg("Failed to find login for sync")
		ce.Reply("Failed to find login: %v", err)
		return
	} else if login == nil {
		if ce.Portal.Relay == nil {
			ce.Reply("No login found for sync")
			return
		} else if !canManageRelay(ce) {
			ce.Reply("Only users with relay management permissions can use sync-portal through the relay")
			return
		}
		login = ce.Portal.Relay
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

var CommandDeleteChat = &FullHandler{
	Func: fnDeleteChat,
	Name: "delete-chat",
	Help: HelpMeta{
		Section:     HelpSectionChats,
		Description: "Delete the current chat on the remote network",
		Args:        "[--for-everyone]",
	},
	RequiresPortal: true,
	RequiresLogin:  true,
	NetworkAPI:     NetworkAPIImplements[bridgev2.DeleteChatHandlingNetworkAPI],
}

func fnDeleteChat(ce *Event) {
	_, api, _ := getClientForStartingChat[bridgev2.DeleteChatHandlingNetworkAPI](ce, "deleting chats")
	err := api.HandleMatrixDeleteChat(ce.Ctx, &bridgev2.MatrixDeleteChat{
		Event: nil,
		Content: &event.BeeperChatDeleteEventContent{
			DeleteForEveryone:  slices.Contains(ce.Args, "--for-everyone"),
			FromMessageRequest: ce.Portal.MessageRequest,
		},
		Portal: ce.Portal,
	})
	if err != nil {
		ce.Reply("Failed to delete chat: %v", err)
	} else {
		ce.React("✅️")
	}
}

var CommandFilter = &FullHandler{
	Func: fnFilter,
	Name: "filter",
	Help: HelpMeta{
		Section:     HelpSectionChats,
		Description: "Manage the room creation filter. Changes are currently in-memory only",
		Args:        "<allow/deny> <chat ID> [receiver]",
	},
	RequiresAdmin: true,
}

func markdownPCFI(pcfi *bridgeconfig.PortalCreateFilterItem) string {
	if pcfi == nil {
		return "<nil>"
	} else if pcfi.Receiver == nil {
		return format.SafeMarkdownCode(pcfi.ID)
	}
	return fmt.Sprintf("%s (receiver: %s)", format.SafeMarkdownCode(pcfi.ID), format.SafeMarkdownCode(*pcfi.Receiver))
}

func fnFilter(ce *Event) {
	if len(ce.Args) < 2 || len(ce.Args) > 3 {
		ce.Reply("Usage: %s <allow/deny> <chat ID> [receiver]", ce.Command)
		return
	}
	target := &bridgeconfig.PortalCreateFilterItem{
		ID: networkid.PortalID(ce.Args[1]),
	}
	if len(ce.Args) == 3 {
		target.Receiver = (*networkid.UserLoginID)(&ce.Args[2])
	}
	pcf := &ce.Bridge.Config.PortalCreateFilter
	found := slices.ContainsFunc(pcf.List, func(item *bridgeconfig.PortalCreateFilterItem) bool {
		return item.Equals(target)
	})
	switch strings.ToLower(ce.Args[0]) {
	case "allow":
		switch pcf.Mode {
		case bridgeconfig.PortalCreateFilterModeAllow:
			if found {
				ce.Reply("%s is already on the allow list", markdownPCFI(target))
			} else {
				pcf.List = append(pcf.List, target)
				ce.Reply("Added %s to allow list", markdownPCFI(target))
			}
		case bridgeconfig.PortalCreateFilterModeDeny:
			if !found {
				ce.Reply("%s is not on the deny list", markdownPCFI(target))
			} else {
				pcf.List = slices.DeleteFunc(pcf.List, func(item *bridgeconfig.PortalCreateFilterItem) bool {
					return item.Equals(target)
				})
				ce.Reply("Removed %s from deny list", markdownPCFI(target))
			}
		}
	case "disallow", "block", "deny":
		switch pcf.Mode {
		case bridgeconfig.PortalCreateFilterModeAllow:
			if !found {
				ce.Reply("%s is not on the allow list", markdownPCFI(target))
			} else {
				pcf.List = slices.DeleteFunc(pcf.List, func(item *bridgeconfig.PortalCreateFilterItem) bool {
					return item.Equals(target)
				})
				ce.Reply("Removed %s from allow list", markdownPCFI(target))
			}
		case bridgeconfig.PortalCreateFilterModeDeny:
			if found {
				ce.Reply("%s is already on the deny list", markdownPCFI(target))
			} else {
				pcf.List = append(pcf.List, target)
				ce.Reply("Added %s to deny list", markdownPCFI(target))
			}
		}
	default:
		ce.Reply("Usage: %s <allow/deny> <chat ID> [receiver]", ce.Command)
	}
}
