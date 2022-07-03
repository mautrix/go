// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"maunium.net/go/mautrix/bridge/bridgeconfig"
)

type MinimalHandler interface {
	Run(*Event)
}

type MinimalHandlerFunc func(*Event)

func (mhf MinimalHandlerFunc) Run(ce *Event) {
	mhf(ce)
}

type Handler interface {
	MinimalHandler
	GetName() string
}

type PermissionedHandler interface {
	Handler
	HasPermission(*Event) bool
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

func (fh *FullHandler) HasPermission(ce *Event) bool {
	return (!fh.RequiresAdmin || ce.User.GetPermissionLevel() >= bridgeconfig.PermissionLevelAdmin) &&
		(!fh.RequiresPortal || ce.Portal != nil) &&
		(!fh.RequiresLogin || ce.User.IsLoggedIn())
}

func (fh *FullHandler) Run(ce *Event) {
	if fh.RequiresAdmin && ce.User.GetPermissionLevel() < bridgeconfig.PermissionLevelAdmin {
		ce.Reply("That command is limited to bridge administrators.")
	} else if fh.RequiresPortal && ce.Portal == nil {
		ce.Reply("That command can only be ran in portal rooms.")
	} else if fh.RequiresLogin && !ce.User.IsLoggedIn() {
		ce.Reply("That command requires you to be logged in")
	} else {
		fh.Func(ce)
	}
}
