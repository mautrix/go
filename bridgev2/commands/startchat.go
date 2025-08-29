// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"fmt"
	"html"
	"strings"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/provisionutil"
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
	NetworkAPI:    NetworkAPIImplements[bridgev2.IdentifierResolvingNetworkAPI],
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
	NetworkAPI:    NetworkAPIImplements[bridgev2.IdentifierResolvingNetworkAPI],
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

func formatResolveIdentifierResult(resp *provisionutil.RespResolveIdentifier) string {
	if resp.MXID != "" {
		return fmt.Sprintf("`%s` / [%s](%s)", resp.ID, resp.Name, resp.MXID.URI().MatrixToURL())
	} else if resp.Name != "" {
		return fmt.Sprintf("`%s` / %s", resp.ID, resp.Name)
	} else {
		return fmt.Sprintf("`%s`", resp.ID)
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
	resp, err := provisionutil.ResolveIdentifier(ce.Ctx, login, identifier, createChat)
	if err != nil {
		ce.Reply("Failed to resolve identifier: %v", err)
		return
	} else if resp == nil {
		ce.ReplyAdvanced(fmt.Sprintf("Identifier <code>%s</code> not found", html.EscapeString(identifier)), false, true)
		return
	}
	formattedName := formatResolveIdentifierResult(resp)
	if createChat {
		name := resp.Portal.Name
		if name == "" {
			name = resp.Portal.MXID.String()
		}
		if !resp.JustCreated {
			ce.Reply("You already have a direct chat with %s at [%s](%s)", formattedName, name, resp.Portal.MXID.URI().MatrixToURL())
		} else {
			ce.Reply("Created chat with %s: [%s](%s)", formattedName, name, resp.Portal.MXID.URI().MatrixToURL())
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
	NetworkAPI:    NetworkAPIImplements[bridgev2.UserSearchingNetworkAPI],
}

func fnSearch(ce *Event) {
	if len(ce.Args) == 0 {
		ce.Reply("Usage: `$cmdprefix search <query>`")
		return
	}
	login, api, queryParts := getClientForStartingChat[bridgev2.UserSearchingNetworkAPI](ce, "searching users")
	if api == nil {
		return
	}
	resp, err := provisionutil.SearchUsers(ce.Ctx, login, strings.Join(queryParts, " "))
	if err != nil {
		ce.Reply("Failed to search for users: %v", err)
		return
	}
	resultsString := make([]string, len(resp.Results))
	for i, res := range resp.Results {
		formattedName := formatResolveIdentifierResult(res)
		resultsString[i] = fmt.Sprintf("* %s", formattedName)
		if res.Portal != nil && res.Portal.MXID != "" {
			portalName := res.Portal.Name
			if portalName == "" {
				portalName = res.Portal.MXID.String()
			}
			resultsString[i] = fmt.Sprintf("%s - DM portal: [%s](%s)", resultsString[i], portalName, res.Portal.MXID.URI().MatrixToURL())
		}
	}
	ce.Reply("Search results:\n\n%s", strings.Join(resultsString, "\n"))
}
