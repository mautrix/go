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
//
// For example:
//
//	go build -ldflags "-X main.Tag=$(git describe --exact-match --tags 2>/dev/null) -X main.Commit=$(git rev-parse HEAD) -X 'main.BuildTime=`date -Iseconds`'"
//
// You may additionally want to fill the mautrix-go version using another ldflag:
//
//	export MAUTRIX_VERSION=$(cat go.mod | grep 'maunium.net/go/mautrix ' | head -n1 | awk '{ print $2 }')
//	go build -ldflags "-X 'maunium.net/go/mautrix.GoModVersion=$MAUTRIX_VERSION'"
//
// (to use both at the same time, merge the ldflags into one, `-ldflags "-X ... -X ..."`)
var (
	Tag       = "unknown"
	Commit    = "unknown"
	BuildTime = "unknown"
)

func ExampleBridgeMain() {
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
