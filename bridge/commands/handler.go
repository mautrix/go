// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"maunium.net/go/mautrix/bridge"
	"maunium.net/go/mautrix/bridge/bridgeconfig"
	"maunium.net/go/mautrix/event"
)

type MinimalHandler interface {
	Run(*Event)
}

type MinimalHandlerFunc func(*Event)

func (mhf MinimalHandlerFunc) Run(ce *Event) {
	mhf(ce)
}

type CommandState struct {
	Next   MinimalHandler
	Action string
	Meta   interface{}
}

type CommandingUser interface {
	bridge.User
	GetCommandState() *CommandState
	SetCommandState(*CommandState)
}

type Handler interface {
	MinimalHandler
	GetName() string
}

type AliasedHandler interface {
	Handler
	GetAliases() []string
}

type FullHandler struct {
	Func func(*Event)

	Name    string
	Aliases []string
	Help    HelpMeta

	RequiresAdmin  bool
	RequiresPortal bool
	RequiresLogin  bool

	RequiresEventLevel event.Type
}

func (fh *FullHandler) GetHelp() HelpMeta {
	fh.Help.Command = fh.Name
	return fh.Help
}

func (fh *FullHandler) GetName() string {
	return fh.Name
}

func (fh *FullHandler) GetAliases() []string {
	return fh.Aliases
}

func (fh *FullHandler) ShowInHelp(ce *Event) bool {
	return !fh.RequiresAdmin || ce.User.GetPermissionLevel() >= bridgeconfig.PermissionLevelAdmin
}

func (fh *FullHandler) userHasRoomPermission(ce *Event) bool {
	levels, err := ce.MainIntent().PowerLevels(ce.Ctx, ce.RoomID)
	if err != nil {
		ce.ZLog.Warn().Err(err).Msg("Failed to check room power levels")
		ce.Reply("Failed to get room power levels to see if you're allowed to use that command")
		return false
	}
	return levels.GetUserLevel(ce.User.GetMXID()) >= levels.GetEventLevel(fh.RequiresEventLevel)
}

func (fh *FullHandler) Run(ce *Event) {
	if fh.RequiresAdmin && ce.User.GetPermissionLevel() < bridgeconfig.PermissionLevelAdmin {
		ce.Reply("That command is limited to bridge administrators.")
	} else if fh.RequiresEventLevel.Type != "" && ce.User.GetPermissionLevel() < bridgeconfig.PermissionLevelAdmin && !fh.userHasRoomPermission(ce) {
		ce.Reply("That command requires room admin rights.")
	} else if fh.RequiresPortal && ce.Portal == nil {
		ce.Reply("That command can only be ran in portal rooms.")
	} else if fh.RequiresLogin && !ce.User.IsLoggedIn() {
		ce.Reply("That command requires you to be logged in.")
	} else {
		fh.Func(ce)
	}
}
