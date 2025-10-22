// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"context"
	"fmt"
	"html"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/provisionutil"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
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
	NetworkAPI:    NetworkAPIImplements[bridgev2.IdentifierResolvingNetworkAPI],
}

var CommandSyncChat = &FullHandler{
	Func: func(ce *Event) {
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
	},
	Name: "sync-portal",
	Help: HelpMeta{
		Section:     HelpSectionChats,
		Description: "Sync the current portal room",
	},
	RequiresPortal: true,
	RequiresLogin:  true,
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
	var remainingArgs []string
	if len(ce.Args) > 1 {
		remainingArgs = ce.Args[1:]
	}
	var login *bridgev2.UserLogin
	if len(ce.Args) > 0 {
		login = ce.Bridge.GetCachedUserLoginByID(networkid.UserLoginID(ce.Args[0]))
	}
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

var CommandCreateGroup = &FullHandler{
	Func:    fnCreateGroup,
	Name:    "create-group",
	Aliases: []string{"create"},
	Help: HelpMeta{
		Section:     HelpSectionChats,
		Description: "Create a new group chat for the current Matrix room",
		Args:        "[_group type_]",
	},
	RequiresLogin: true,
	NetworkAPI:    NetworkAPIImplements[bridgev2.GroupCreatingNetworkAPI],
}

func getState[T any](ctx context.Context, roomID id.RoomID, evtType event.Type, provider bridgev2.MatrixConnectorWithArbitraryRoomState) (content T) {
	evt, err := provider.GetStateEvent(ctx, roomID, evtType, "")
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Stringer("event_type", evtType).Msg("Failed to get state event for group creation")
	} else if evt != nil {
		content, _ = evt.Content.Parsed.(T)
	}
	return
}

func fnCreateGroup(ce *Event) {
	ce.Bridge.Matrix.GetCapabilities()
	login, api, remainingArgs := getClientForStartingChat[bridgev2.GroupCreatingNetworkAPI](ce, "creating group")
	if api == nil {
		return
	}
	stateProvider, ok := ce.Bridge.Matrix.(bridgev2.MatrixConnectorWithArbitraryRoomState)
	if !ok {
		ce.Reply("Matrix connector doesn't support fetching room state")
		return
	}
	members, err := ce.Bridge.Matrix.GetMembers(ce.Ctx, ce.RoomID)
	if err != nil {
		ce.Log.Err(err).Msg("Failed to get room members for group creation")
		ce.Reply("Failed to get room members: %v", err)
		return
	}
	caps := ce.Bridge.Network.GetCapabilities()
	params := &bridgev2.GroupCreateParams{
		Username:     "",
		Participants: make([]networkid.UserID, 0, len(members)-2),
		Parent:       nil, // TODO check space parent event
		Name:         getState[*event.RoomNameEventContent](ce.Ctx, ce.RoomID, event.StateRoomName, stateProvider),
		Avatar:       getState[*event.RoomAvatarEventContent](ce.Ctx, ce.RoomID, event.StateRoomAvatar, stateProvider),
		Topic:        getState[*event.TopicEventContent](ce.Ctx, ce.RoomID, event.StateTopic, stateProvider),
		Disappear:    getState[*event.BeeperDisappearingTimer](ce.Ctx, ce.RoomID, event.StateBeeperDisappearingTimer, stateProvider),
		RoomID:       ce.RoomID,
	}
	for userID, member := range members {
		if userID == ce.User.MXID || userID == ce.Bot.GetMXID() || !member.Membership.IsInviteOrJoin() {
			continue
		}
		if parsedUserID, ok := ce.Bridge.Matrix.ParseGhostMXID(userID); ok {
			params.Participants = append(params.Participants, parsedUserID)
		} else if !ce.Bridge.Config.SplitPortals {
			if user, err := ce.Bridge.GetExistingUserByMXID(ce.Ctx, userID); err != nil {
				ce.Log.Err(err).Stringer("user_id", userID).Msg("Failed to get user for room member")
			} else if user != nil {
				// TODO add user logins to participants
				//for _, login := range user.GetUserLogins() {
				//	params.Participants = append(params.Participants, login.GetUserID())
				//}
			}
		}
	}

	if len(caps.Provisioning.GroupCreation) == 0 {
		ce.Reply("No group creation types defined in network capabilities")
		return
	} else if len(remainingArgs) > 0 {
		params.Type = remainingArgs[0]
	} else if len(caps.Provisioning.GroupCreation) == 1 {
		for params.Type = range caps.Provisioning.GroupCreation {
			// The loop assigns the variable we want
		}
	} else {
		types := strings.Join(slices.Collect(maps.Keys(caps.Provisioning.GroupCreation)), "`, `")
		ce.Reply("Please specify type of group to create: `%s`", types)
		return
	}
	resp, err := provisionutil.CreateGroup(ce.Ctx, login, params)
	if err != nil {
		ce.Reply("Failed to create group: %v", err)
		return
	}
	var postfix string
	if len(resp.FailedParticipants) > 0 {
		failedParticipantsStrings := make([]string, len(resp.FailedParticipants))
		i := 0
		for participantID, meta := range resp.FailedParticipants {
			failedParticipantsStrings[i] = fmt.Sprintf("* %s: %s", format.SafeMarkdownCode(participantID), meta.Reason)
			i++
		}
		postfix += "\n\nFailed to add some participants:\n" + strings.Join(failedParticipantsStrings, "\n")
	}
	ce.Reply("Successfully created group `%s`%s", resp.ID, postfix)
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
