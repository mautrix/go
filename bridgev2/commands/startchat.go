// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/net/html"

	"maunium.net/go/mautrix/bridgev2"

	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/id"
)

var CommandResolveIdentifier = &FullHandler{
	Func: fnResolveIdentifier,
	Name: "resolve-identifier",
	Help: HelpMeta{
		Section:     HelpSectionChats,
		Description: "Check if a given identifier is on the remote network",
		Args:        "[_login ID_] <_identifier_>",
	},
	RequiresLogin: true,
}

var CommandStartChat = &FullHandler{
	Func: fnResolveIdentifier,
	Name: "start-chat",
	Help: HelpMeta{
		Section:     HelpSectionChats,
		Description: "Start a direct chat with the given user",
		Args:        "[_login ID_] <_identifier_>",
	},
	RequiresLogin: true,
}

func getClientForStartingChat[T bridgev2.IdentifierResolvingNetworkAPI](ce *Event, thing string) (*bridgev2.UserLogin, T, []string) {
	remainingArgs := ce.Args[1:]
	login := ce.Bridge.GetCachedUserLoginByID(networkid.UserLoginID(ce.Args[0]))
	if login == nil || login.UserMXID != ce.User.MXID {
		remainingArgs = ce.Args
		login = ce.User.GetDefaultLogin()
	}
	api, ok := login.Client.(T)
	if !ok {
		ce.Reply("This bridge does not support %s", thing)
	}
	return login, api, remainingArgs
}

func fnResolveIdentifier(ce *Event) {
	login, api, identifierParts := getClientForStartingChat[bridgev2.IdentifierResolvingNetworkAPI](ce, "resolving identifiers")
	if api == nil {
		return
	}
	createChat := ce.Command == "start-chat"
	identifier := strings.Join(identifierParts, " ")
	resp, err := api.ResolveIdentifier(ce.Ctx, identifier, createChat)
	if err != nil {
		ce.Reply("Failed to resolve identifier: %v", err)
		return
	} else if resp == nil {
		ce.ReplyAdvanced(fmt.Sprintf("Identifier <code>%s</code> not found", html.EscapeString(identifier)), false, true)
		return
	}
	var targetName string
	var targetMXID id.UserID
	if resp.Ghost != nil {
		if resp.UserInfo != nil {
			resp.Ghost.UpdateInfo(ce.Ctx, resp.UserInfo)
		}
		targetName = resp.Ghost.Name
		targetMXID = resp.Ghost.Intent.GetMXID()
	} else if resp.UserInfo != nil && resp.UserInfo.Name != nil {
		targetName = *resp.UserInfo.Name
	}
	var formattedName string
	if targetMXID != "" {
		formattedName = fmt.Sprintf("`%s` / [%s](%s)", resp.UserID, targetName, targetMXID.URI().MatrixToURL())
	} else if targetName != "" {
		formattedName = fmt.Sprintf("`%s` / %s", resp.UserID, targetName)
	} else {
		formattedName = fmt.Sprintf("`%s`", resp.UserID)
	}
	if createChat {
		if resp.Chat == nil {
			ce.Reply("Interface error: network connector did not return chat for create chat request")
			return
		}
		portal := resp.Chat.Portal
		if portal == nil {
			portal, err = ce.Bridge.GetPortalByID(ce.Ctx, resp.Chat.PortalID)
			if err != nil {
				ce.Reply("Failed to get portal: %v", err)
				return
			}
		}
		if portal.MXID != "" {
			name := portal.Name
			if name == "" {
				name = portal.MXID.String()
			}
			portal.UpdateInfo(ce.Ctx, resp.Chat.PortalInfo, login, nil, time.Time{})
			ce.Reply("You already have a direct chat with %s at [%s](%s)", formattedName, name, portal.MXID.URI().MatrixToURL())
		} else {
			err = portal.CreateMatrixRoom(ce.Ctx, login, resp.Chat.PortalInfo)
			if err != nil {
				ce.Reply("Failed to create room: %v", err)
				return
			}
			name := portal.Name
			if name == "" {
				name = portal.MXID.String()
			}
			ce.Reply("Created chat with %s: [%s](%s)", formattedName, name, portal.MXID.URI().MatrixToURL())
		}
	} else {
		ce.Reply("Found %s", formattedName)
	}
}

var CommandDeletePortal = &FullHandler{
	Func: func(ce *Event) {
		err := ce.Portal.Delete(ce.Ctx)
		if err != nil {
			ce.Reply("Failed to delete portal: %v", err)
		}
		err = ce.Bot.DeleteRoom(ce.Ctx, ce.Portal.MXID, false)
		if err != nil {
			ce.Reply("Failed to clean up room: %v", err)
		}
	},
	Name: "delete-portal",
	Help: HelpMeta{
		Section:     HelpSectionAdmin,
		Description: "Delete the current portal room",
	},
	RequiresAdmin:  true,
	RequiresPortal: true,
}
