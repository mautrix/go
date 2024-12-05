// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"context"
	"fmt"
	"html"
	"strings"
	"time"

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
	Func:    fnResolveIdentifier,
	Name:    "start-chat",
	Aliases: []string{"pm"},
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

func formatResolveIdentifierResult(ctx context.Context, resp *bridgev2.ResolveIdentifierResponse) string {
	var targetName string
	var targetMXID id.UserID
	if resp.Ghost != nil {
		if resp.UserInfo != nil {
			resp.Ghost.UpdateInfo(ctx, resp.UserInfo)
		}
		targetName = resp.Ghost.Name
		targetMXID = resp.Ghost.Intent.GetMXID()
	} else if resp.UserInfo != nil && resp.UserInfo.Name != nil {
		targetName = *resp.UserInfo.Name
	}
	if targetMXID != "" {
		return fmt.Sprintf("`%s` / [%s](%s)", resp.UserID, targetName, targetMXID.URI().MatrixToURL())
	} else if targetName != "" {
		return fmt.Sprintf("`%s` / %s", resp.UserID, targetName)
	} else {
		return fmt.Sprintf("`%s`", resp.UserID)
	}
}

func fnResolveIdentifier(ce *Event) {
	if len(ce.Args) == 0 {
		ce.Reply("Usage: `$cmdprefix %s <identifier>`", ce.Command)
		return
	}
	login, api, identifierParts := getClientForStartingChat[bridgev2.IdentifierResolvingNetworkAPI](ce, "resolving identifiers")
	if api == nil {
		return
	}
	createChat := ce.Command == "start-chat" || ce.Command == "pm"
	identifier := strings.Join(identifierParts, " ")
	resp, err := api.ResolveIdentifier(ce.Ctx, identifier, createChat)
	if err != nil {
		ce.Log.Err(err).Msg("Failed to resolve identifier")
		ce.Reply("Failed to resolve identifier: %v", err)
		return
	} else if resp == nil {
		ce.ReplyAdvanced(fmt.Sprintf("Identifier <code>%s</code> not found", html.EscapeString(identifier)), false, true)
		return
	}
	formattedName := formatResolveIdentifierResult(ce.Ctx, resp)
	if createChat {
		if resp.Chat == nil {
			ce.Reply("Interface error: network connector did not return chat for create chat request")
			return
		}
		portal := resp.Chat.Portal
		if portal == nil {
			portal, err = ce.Bridge.GetPortalByKey(ce.Ctx, resp.Chat.PortalKey)
			if err != nil {
				ce.Log.Err(err).Msg("Failed to get portal")
				ce.Reply("Failed to get portal: %v", err)
				return
			}
		}
		if resp.Chat.PortalInfo == nil {
			resp.Chat.PortalInfo, err = api.GetChatInfo(ce.Ctx, portal)
			if err != nil {
				ce.Log.Err(err).Msg("Failed to get portal info")
				ce.Reply("Failed to get portal info: %v", err)
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
				ce.Log.Err(err).Msg("Failed to create room")
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

var CommandSearch = &FullHandler{
	Func: fnSearch,
	Name: "search",
	Help: HelpMeta{
		Section:     HelpSectionChats,
		Description: "Search for users on the remote network",
		Args:        "<_query_>",
	},
	RequiresLogin: true,
}

func fnSearch(ce *Event) {
	if len(ce.Args) == 0 {
		ce.Reply("Usage: `$cmdprefix search <query>`")
		return
	}
	_, api, queryParts := getClientForStartingChat[bridgev2.UserSearchingNetworkAPI](ce, "searching users")
	if api == nil {
		return
	}
	results, err := api.SearchUsers(ce.Ctx, strings.Join(queryParts, " "))
	if err != nil {
		ce.Log.Err(err).Msg("Failed to search for users")
		ce.Reply("Failed to search for users: %v", err)
		return
	}
	resultsString := make([]string, len(results))
	for i, res := range results {
		formattedName := formatResolveIdentifierResult(ce.Ctx, res)
		resultsString[i] = fmt.Sprintf("* %s", formattedName)
		if res.Chat != nil {
			if res.Chat.Portal == nil {
				res.Chat.Portal, err = ce.Bridge.GetExistingPortalByKey(ce.Ctx, res.Chat.PortalKey)
				if err != nil {
					ce.Log.Err(err).Object("portal_key", res.Chat.PortalKey).Msg("Failed to get DM portal")
				}
			}
			if res.Chat.Portal != nil && res.Chat.Portal.MXID != "" {
				portalName := res.Chat.Portal.Name
				if portalName == "" {
					portalName = res.Chat.Portal.MXID.String()
				}
				resultsString[i] = fmt.Sprintf("%s - DM portal: [%s](%s)", resultsString[i], portalName, res.Chat.Portal.MXID.URI().MatrixToURL())
			}
		}
	}
	ce.Reply("Search results:\n\n%s", strings.Join(resultsString, "\n"))
}
