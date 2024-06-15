// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mxmain_test

import (
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/matrix/mxmain"
)

// Information to find out exactly which commit the bridge was built from.
// These are filled at build time with the -X linker flag.
var (
	Tag       = "unknown"
	Commit    = "unknown"
	BuildTime = "unknown"
)

func ExampleBridgeMain() {
	// Set this yourself
	var yourConnector bridgev2.NetworkConnector

	m := mxmain.BridgeMain{
		Name:        "example-matrix-bridge",
		URL:         "https://github.com/octocat/matrix-bridge",
		Description: "An example Matrix bridge.",
		Version:     "1.0.0",

		Connector: yourConnector,
	}
	m.PostInit = func() {
		// If you want some code to run after all the setup is done, but before the bridge is started,
		// you can set a function in PostInit. This is not required if you don't need to do anything special.
	}
	m.InitVersion(Tag, Commit, BuildTime)
	m.Run()
}
