// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"fmt"

	sync "github.com/sasha-s/go-deadlock"

	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix/bridge/status"
	"maunium.net/go/mautrix/bridgev2/bridgeconfig"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/id"
)

type CommandProcessor interface {
	Handle(ctx context.Context, roomID id.RoomID, eventID id.EventID, user *User, message string, replyTo id.EventID)
}

type Bridge struct {
	ID  networkid.BridgeID
	DB  *database.Database
	Log zerolog.Logger

	Matrix   MatrixConnector
	Bot      MatrixAPI
	Network  NetworkConnector
	Commands CommandProcessor
	Config   *bridgeconfig.BridgeConfig

	DisappearLoop *DisappearLoop

	usersByMXID    map[id.UserID]*User
	userLoginsByID map[networkid.UserLoginID]*UserLogin
	portalsByKey   map[networkid.PortalKey]*Portal
	portalsByMXID  map[id.RoomID]*Portal
	ghostsByID     map[networkid.UserID]*Ghost
	cacheLock      sync.Mutex

	wakeupBackfillQueue chan struct{}
	stopBackfillQueue   chan struct{}
}

func NewBridge(
	bridgeID networkid.BridgeID,
	db *dbutil.Database,
	log zerolog.Logger,
	cfg *bridgeconfig.BridgeConfig,
	matrix MatrixConnector,
	network NetworkConnector,
	newCommandProcessor func(*Bridge) CommandProcessor,
) *Bridge {
	br := &Bridge{
		ID:  bridgeID,
		DB:  database.New(bridgeID, network.GetDBMetaTypes(), db),
		Log: log,

		Matrix:  matrix,
		Network: network,
		Config:  cfg,

		usersByMXID:    make(map[id.UserID]*User),
		userLoginsByID: make(map[networkid.UserLoginID]*UserLogin),
		portalsByKey:   make(map[networkid.PortalKey]*Portal),
		portalsByMXID:  make(map[id.RoomID]*Portal),
		ghostsByID:     make(map[networkid.UserID]*Ghost),

		wakeupBackfillQueue: make(chan struct{}),
		stopBackfillQueue:   make(chan struct{}),
	}
	if br.Config == nil {
		br.Config = &bridgeconfig.BridgeConfig{CommandPrefix: "!bridge"}
	}
	br.Commands = newCommandProcessor(br)
	br.Matrix.Init(br)
	br.Bot = br.Matrix.BotIntent()
	br.Network.Init(br)
	br.DisappearLoop = &DisappearLoop{br: br}
	return br
}

type DBUpgradeError struct {
	Err     error
	Section string
}

func (e DBUpgradeError) Error() string {
	return e.Err.Error()
}

func (e DBUpgradeError) Unwrap() error {
	return e.Err
}

func (br *Bridge) Start() error {
	err := br.StartConnectors()
	if err != nil {
		return err
	}
	err = br.StartLogins()
	if err != nil {
		return err
	}
	return nil
}

func (br *Bridge) StartConnectors() error {
	br.Log.Info().Msg("Starting bridge")
	ctx := br.Log.WithContext(context.Background())

	err := br.DB.Upgrade(ctx)
	if err != nil {
		return DBUpgradeError{Err: err, Section: "main"}
	}
	br.Log.Info().Msg("Starting Matrix connector")
	err = br.Matrix.Start(ctx)
	if err != nil {
		return fmt.Errorf("failed to start Matrix connector: %w", err)
	}
	br.Log.Info().Msg("Starting network connector")
	err = br.Network.Start(ctx)
	if err != nil {
		return fmt.Errorf("failed to start network connector: %w", err)
	}
	if br.Network.GetCapabilities().DisappearingMessages {
		go br.DisappearLoop.Start()
	}
	return nil
}

func (br *Bridge) StartLogins() error {
	ctx := br.Log.WithContext(context.Background())

	userIDs, err := br.DB.UserLogin.GetAllUserIDsWithLogins(ctx)
	if err != nil {
		return fmt.Errorf("failed to get users with logins: %w", err)
	}
	startedAny := false
	for _, userID := range userIDs {
		br.Log.Info().Stringer("user_id", userID).Msg("Loading user")
		var user *User
		user, err = br.GetUserByMXID(ctx, userID)
		if err != nil {
			br.Log.Err(err).Stringer("user_id", userID).Msg("Failed to load user")
		} else {
			for _, login := range user.GetUserLogins() {
				startedAny = true
				br.Log.Info().Str("id", string(login.ID)).Msg("Starting user login")
				err = login.Client.Connect(login.Log.WithContext(ctx))
				if err != nil {
					br.Log.Err(err).Msg("Failed to connect existing client")
				}
			}
		}
	}
	if !startedAny {
		br.Log.Info().Msg("No user logins found")
		br.SendGlobalBridgeState(status.BridgeState{StateEvent: status.StateUnconfigured})
	}
	go br.RunBackfillQueue()

	br.Log.Info().Msg("Bridge started")
	return nil
}

func (br *Bridge) Stop() {
	br.Log.Info().Msg("Shutting down bridge")
	close(br.stopBackfillQueue)
	br.Matrix.Stop()
	br.cacheLock.Lock()
	var wg sync.WaitGroup
	wg.Add(len(br.userLoginsByID))
	for _, login := range br.userLoginsByID {
		go login.Disconnect(wg.Done)
	}
	wg.Wait()
	br.cacheLock.Unlock()
	err := br.DB.Close()
	if err != nil {
		br.Log.Warn().Err(err).Msg("Failed to close database")
	}
	br.Log.Info().Msg("Shutdown complete")
}
