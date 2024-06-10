// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/exerrors"

	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"

	"maunium.net/go/mautrix/id"
)

var ErrNotLoggedIn = errors.New("not logged in")

type Bridge struct {
	ID  networkid.BridgeID
	DB  *database.Database
	Log zerolog.Logger

	Matrix   MatrixConnector
	Bot      MatrixAPI
	Network  NetworkConnector
	Commands *CommandProcessor

	// TODO move to config
	CommandPrefix string

	usersByMXID    map[id.UserID]*User
	userLoginsByID map[networkid.UserLoginID]*UserLogin
	portalsByKey   map[networkid.PortalKey]*Portal
	portalsByMXID  map[id.RoomID]*Portal
	ghostsByID     map[networkid.UserID]*Ghost
	cacheLock      sync.Mutex
}

func NewBridge(bridgeID networkid.BridgeID, db *dbutil.Database, log zerolog.Logger, matrix MatrixConnector, network NetworkConnector) *Bridge {
	br := &Bridge{
		ID:  bridgeID,
		DB:  database.New(bridgeID, db),
		Log: log,

		Matrix:  matrix,
		Network: network,

		usersByMXID:    make(map[id.UserID]*User),
		userLoginsByID: make(map[networkid.UserLoginID]*UserLogin),
		portalsByKey:   make(map[networkid.PortalKey]*Portal),
		portalsByMXID:  make(map[id.RoomID]*Portal),
		ghostsByID:     make(map[networkid.UserID]*Ghost),
	}
	br.Commands = NewProcessor(br)
	br.Matrix.Init(br)
	br.Bot = br.Matrix.BotIntent()
	br.Network.Init(br)
	return br
}

func (br *Bridge) Start() {
	br.Log.Info().Msg("Starting bridge")
	ctx := br.Log.WithContext(context.Background())

	exerrors.PanicIfNotNil(br.DB.Upgrade(ctx))
	br.Log.Info().Msg("Starting Matrix connector")
	exerrors.PanicIfNotNil(br.Matrix.Start(ctx))
	br.Log.Info().Msg("Starting network connector")
	exerrors.PanicIfNotNil(br.Network.Start(ctx))

	logins, err := br.GetAllUserLogins(ctx)
	if err != nil {
		br.Log.Fatal().Err(err).Msg("Failed to get user logins")
	}
	for _, login := range logins {
		br.Log.Info().Str("id", string(login.ID)).Msg("Starting user login")
		err = login.Client.Connect(login.Log.WithContext(ctx))
		if err != nil {
			br.Log.Err(err).Msg("Failed to connect existing client")
		}
	}
	if len(logins) == 0 {
		br.Log.Info().Msg("No user logins found")
	}

	br.Log.Info().Msg("Bridge started")
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	br.Log.Info().Msg("Shutting down bridge")
}
