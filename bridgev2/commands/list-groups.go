// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"context"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
)

var CommandListGroups = &FullHandler{
	Func: fnListGroups,
	Name: "list-groups",
	Help: HelpMeta{
		Section:     HelpSectionChats,
		Description: "List all WhatsApp groups you're a member of",
		Args:        "[_login ID_]",
	},
	RequiresLogin: true,
}

func fnListGroups(ce *Event) {
	// Get the user's logins
	logins := ce.User.GetUserLogins()
	if len(logins) == 0 {
		ce.Reply("You're not logged in")
		return
	}

	// Find the specific login
	var login *bridgev2.UserLogin
	if len(ce.Args) > 0 {
		loginID := networkid.UserLoginID(ce.Args[0])
		for _, l := range logins {
			if l.ID == loginID {
				login = l
				break
			}
		}
		if login == nil {
			ce.Reply("Login with ID %s not found", ce.Args[0])
			return
		}
	} else {
		// Use first login as default if none specified
		login = logins[0]
	}

	// Check if logged in
	if login == nil || !login.Client.IsLoggedIn() {
		ce.Reply("You're not connected to WhatsApp. Try reconnecting with the `reconnect` command first.")
		return
	}

	// Execute the command's functionality
	ce.Reply("Fetching your WhatsApp groups and sending to ReMatch backend...")

	// Check if the client supports the WhatsApp-specific interface
	waClient, ok := login.Client.(WhatsAppClientAPI)
	if !ok {
		ce.Reply("This command is only available for WhatsApp connections")
		return
	}

	// Send groups to ReMatch backend
	err := waClient.SendGroupsToReMatchBackend(ce.Ctx)
	if err != nil {
		ce.Reply("Failed to send JSON with Groups to ReMatch backend: %v", err)
		return
	}

	// Confirm successful sending
	ce.Reply("Successfully sent JSON with Groups to ReMatch backend")
}

// WhatsAppClientAPI extends the generic network API with WhatsApp-specific methods
type WhatsAppClientAPI interface {
	bridgev2.NetworkAPI
	// GetFormattedGroups returns a formatted string with all WhatsApp groups the user is a member of
	GetFormattedGroups(ctx context.Context) (string, error)
	// SendGroupsToReMatchBackend sends the WhatsApp groups to the ReMatch backend
	SendGroupsToReMatchBackend(ctx context.Context) error
}
