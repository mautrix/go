// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/exhttp"
	"go.mau.fi/util/exsync"

	"maunium.net/go/mautrix/bridgev2/bridgeconfig"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/status"
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

	didSplitPortals bool

	Background          bool
	ExternallyManagedDB bool
	stopping            atomic.Bool

	wakeupBackfillQueue chan struct{}
	stopBackfillQueue   *exsync.Event
	manualBackfills     chan *ManualBackfill

	BackgroundCtx       context.Context
	cancelBackgroundCtx context.CancelFunc
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
		manualBackfills:     make(chan *ManualBackfill, 64),
		stopBackfillQueue:   exsync.NewEvent(),
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

func (br *Bridge) Start(ctx context.Context) error {
	ctx = br.Log.WithContext(ctx)
	err := br.StartConnectors(ctx)
	if err != nil {
		return err
	}
	err = br.StartLogins(ctx)
	if err != nil {
		return err
	}
	go br.PostStart(ctx)
	return nil
}

func (br *Bridge) RunOnce(ctx context.Context, loginID networkid.UserLoginID, params *ConnectBackgroundParams) error {
	br.Background = true
	br.stopping.Store(false)
	err := br.StartConnectors(ctx)
	if err != nil {
		return err
	}

	if loginID == "" {
		br.Log.Info().Msg("No login ID provided to RunOnce, running all logins for 20 seconds")
		err = br.StartLogins(ctx)
		if err != nil {
			return err
		}
		defer br.StopWithTimeout(5 * time.Second)
		select {
		case <-time.After(20 * time.Second):
		case <-ctx.Done():
		}
		return nil
	}

	defer br.stop(true, 5*time.Second)
	login, err := br.GetExistingUserLoginByID(ctx, loginID)
	if err != nil {
		return fmt.Errorf("failed to get user login: %w", err)
	} else if login == nil {
		return ErrNotLoggedIn
	}
	syncClient, ok := login.Client.(BackgroundSyncingNetworkAPI)
	if !ok {
		br.Log.Warn().Msg("Network connector doesn't implement background mode, using fallback mechanism for RunOnce")
		login.Client.Connect(ctx)
		defer login.DisconnectWithTimeout(5 * time.Second)
		select {
		case <-time.After(20 * time.Second):
		case <-ctx.Done():
		}
		br.stopping.Store(true)
		return nil
	} else {
		br.Log.Info().Str("user_login_id", string(login.ID)).Msg("Starting individual user login in background mode")
		return syncClient.ConnectBackground(login.Log.WithContext(ctx), params)
	}
}

func (br *Bridge) StartConnectors(ctx context.Context) error {
	br.Log.Info().Msg("Starting bridge")
	br.stopping.Store(false)
	if br.BackgroundCtx == nil || br.BackgroundCtx.Err() != nil {
		br.BackgroundCtx, br.cancelBackgroundCtx = context.WithCancel(context.Background())
		br.BackgroundCtx = br.Log.WithContext(br.BackgroundCtx)
	}

	if !br.ExternallyManagedDB {
		err := br.DB.Upgrade(ctx)
		if err != nil {
			return DBUpgradeError{Err: err, Section: "main"}
		}
	}
	if !br.Background {
		didSplitPortals, err := br.MigrateToSplitPortals(ctx)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrSplitPortalMigrationFailed, err)
		}
		br.didSplitPortals = didSplitPortals
	}
	br.Log.Info().Msg("Starting Matrix connector")
	err := br.Matrix.Start(ctx)
	if err != nil {
		return fmt.Errorf("failed to start Matrix connector: %w", err)
	}
	br.Log.Info().Msg("Starting network connector")
	err = br.Network.Start(ctx)
	if err != nil {
		return fmt.Errorf("failed to start network connector: %w", err)
	}
	if br.Network.GetCapabilities().DisappearingMessages && !br.Background {
		go br.DisappearLoop.Start()
	}
	return nil
}

func (br *Bridge) PostStart(ctx context.Context) {
	if br.Background {
		return
	}
	br.cleanupPortalsWithoutReceiver(ctx)
	rawBridgeInfoVer := br.DB.KV.Get(ctx, database.KeyBridgeInfoVersion)
	bridgeInfoVer, capVer, err := parseBridgeInfoVersion(rawBridgeInfoVer)
	if err != nil {
		br.Log.Err(err).Str("db_bridge_info_version", rawBridgeInfoVer).Msg("Failed to parse bridge info version")
		return
	}
	expectedBridgeInfoVer, expectedCapVer := br.Network.GetBridgeInfoVersion()
	doResendBridgeInfo := bridgeInfoVer != expectedBridgeInfoVer || br.didSplitPortals || br.Config.ResendBridgeInfo
	doResendCapabilities := capVer != expectedCapVer || br.didSplitPortals
	if doResendBridgeInfo || doResendCapabilities {
		br.ResendBridgeInfo(ctx, doResendBridgeInfo, doResendCapabilities)
	}
	br.DB.KV.Set(ctx, database.KeyBridgeInfoVersion, fmt.Sprintf("%d,%d", expectedBridgeInfoVer, expectedCapVer))
}

func (br *Bridge) GetBeeperStreamPublisher() BeeperStreamPublisher {
	if br == nil || br.Matrix == nil {
		return nil
	}
	withStreams, ok := br.Matrix.(MatrixConnectorWithBeeperStreams)
	if !ok {
		return nil
	}
	return withStreams.GetBeeperStreamPublisher()
}

func parseBridgeInfoVersion(version string) (info, capabilities int, err error) {
	_, err = fmt.Sscanf(version, "%d,%d", &info, &capabilities)
	if version == "" {
		err = nil
	}
	return
}

func (br *Bridge) ResendBridgeInfo(ctx context.Context, resendInfo, resendCaps bool) {
	log := zerolog.Ctx(ctx).With().Str("action", "resend bridge info").Logger()
	portals, err := br.GetAllPortalsWithMXID(ctx)
	if err != nil {
		log.Err(err).Msg("Failed to get portals")
		return
	}
	for _, portal := range portals {
		if resendInfo {
			portal.UpdateBridgeInfo(ctx)
		}
		if resendCaps {
			logins, err := br.GetUserLoginsInPortal(ctx, portal.PortalKey)
			if err != nil {
				log.Err(err).
					Stringer("room_id", portal.MXID).
					Object("portal_key", portal.PortalKey).
					Msg("Failed to get user logins in portal")
			} else {
				found := false
				for _, login := range logins {
					if portal.CapState.ID == "" || login.ID == portal.CapState.Source {
						portal.UpdateCapabilities(ctx, login, true)
						found = true
					}
				}
				if !found && len(logins) > 0 {
					portal.CapState.Source = ""
					portal.UpdateCapabilities(ctx, logins[0], true)
				} else if !found {
					log.Warn().
						Stringer("room_id", portal.MXID).
						Object("portal_key", portal.PortalKey).
						Msg("No user login found to update capabilities")
				}
			}
		}
	}
	log.Info().
		Bool("capabilities", resendCaps).
		Bool("info", resendInfo).
		Msg("Resent bridge info to all portals")
}

func (br *Bridge) MigrateToSplitPortals(ctx context.Context) (bool, error) {
	log := zerolog.Ctx(ctx).With().Str("action", "migrate to split portals").Logger()
	ctx = log.WithContext(ctx)
	if !br.Config.SplitPortals || br.DB.KV.Get(ctx, database.KeySplitPortalsEnabled) == "true" {
		return false, nil
	}
	affected, err := br.DB.Portal.MigrateToSplitPortals(ctx)
	if err != nil {
		log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Failed to migrate portals")
		return false, fmt.Errorf("failed to migrate database: %w", err)
	}
	log.Info().Int64("rows_affected", affected).Msg("Migrated to split portals")
	affected2, err := br.DB.Portal.FixParentsAfterSplitPortalMigration(ctx)
	if err != nil {
		log.Err(err).Msg("Failed to fix parent portals after split portal migration")
		return false, fmt.Errorf("failed to fix parent portals: %w", err)
	}
	log.Info().Int64("rows_affected", affected2).Msg("Updated parent receivers after split portal migration")
	br.DB.KV.Set(ctx, database.KeySplitPortalsEnabled, "true")
	log.Info().Msg("Finished split portal migration successfully")
	return affected > 0, nil
}

// Second part of MigrateToSplitPortals: remove those without any receiver set - this has to run
// once the bridge is started (so we can pass the deletion to Matrix) and so must be asynchronous,
// and re-run every bridge start in case of prior crash.
func (br *Bridge) cleanupPortalsWithoutReceiver(ctx context.Context) {
	if !br.Config.SplitPortals {
		return
	}
	log := zerolog.Ctx(ctx).With().Str("action", "cleanup portals without receiver").Logger()
	ctx = log.WithContext(ctx)
	withoutReceiver, err := br.DB.Portal.GetAllWithoutReceiver(ctx)
	if err != nil {
		log.Err(err).Msg("Failed to get portals without receiver to clean up")
		return
	}
	if len(withoutReceiver) == 0 {
		return
	}
	log.Info().Int("portal_count", len(withoutReceiver)).Msg("Cleaning up portals that couldn't be migrated to split portals")
	deleted := 0
	for _, portal := range withoutReceiver {
		if portal.MXID != "" {
			if err = br.Bot.DeleteRoom(ctx, portal.MXID, true); err != nil {
				log.Err(err).
					Str("portal_id", string(portal.ID)).
					Stringer("mxid", portal.MXID).
					Msg("Failed to delete room for un-migratable portal, keeping row and retrying next start")
				continue
			}
		}
		if err = br.DB.Portal.Delete(ctx, portal.PortalKey); err != nil {
			log.Err(err).
				Str("portal_id", string(portal.ID)).
				Stringer("mxid", portal.MXID).
				Msg("Failed to delete portal row after room teardown")
			continue
		}
		deleted++
	}
	log.Info().
		Int("deleted", deleted).
		Int("remaining", len(withoutReceiver)-deleted).
		Msg("Finished cleaning up portals without receiver")
}

func (br *Bridge) StartLogins(ctx context.Context) error {
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
				login.Client.Connect(login.Log.WithContext(ctx))
			}
		}
	}
	if !startedAny {
		br.Log.Info().Msg("No user logins found")
		br.SendGlobalBridgeState(status.BridgeState{StateEvent: status.StateUnconfigured})
	}
	if !br.Background {
		go br.RunBackfillQueue()
	}

	br.Log.Info().Msg("Bridge started")
	return nil
}

func (br *Bridge) ResetNetworkConnections() {
	nrn, ok := br.Network.(NetworkResettingNetwork)
	if ok {
		br.Log.Info().Msg("Resetting network connections with NetworkConnector.ResetNetworkConnections")
		nrn.ResetNetworkConnections()
		return
	}

	br.Log.Info().Msg("Network connector doesn't support ResetNetworkConnections, recreating clients manually")
	for _, login := range br.GetAllCachedUserLogins() {
		login.Log.Debug().Msg("Disconnecting and recreating client for network reset")
		ctx := login.Log.WithContext(br.BackgroundCtx)
		login.Client.Disconnect()
		err := login.recreateClient(ctx)
		if err != nil {
			login.Log.Err(err).Msg("Failed to recreate client during network reset")
			login.BridgeState.Send(status.BridgeState{
				StateEvent: status.StateUnknownError,
				Error:      "bridgev2-network-reset-fail",
				Info:       map[string]any{"go_error": err.Error()},
			})
		} else {
			login.Client.Connect(ctx)
		}
	}
	br.Log.Info().Msg("Finished resetting all user logins")
}

func (br *Bridge) GetHTTPClientSettings() exhttp.ClientSettings {
	mchs, ok := br.Matrix.(MatrixConnectorWithHTTPSettings)
	if ok {
		return mchs.GetHTTPClientSettings()
	}
	return exhttp.SensibleClientSettings
}

func (br *Bridge) IsStopping() bool {
	return br.stopping.Load()
}

func (br *Bridge) Stop() {
	br.stop(false, 0)
}

func (br *Bridge) StopWithTimeout(timeout time.Duration) {
	br.stop(false, timeout)
}

func (br *Bridge) stop(isRunOnce bool, timeout time.Duration) {
	br.Log.Info().Msg("Shutting down bridge")
	br.stopping.Store(true)
	br.DisappearLoop.Stop()
	br.stopBackfillQueue.Set()
	br.Matrix.PreStop()
	if !isRunOnce {
		br.cacheLock.Lock()
		var wg sync.WaitGroup
		wg.Add(len(br.userLoginsByID))
		for _, login := range br.userLoginsByID {
			go func() {
				login.DisconnectWithTimeout(timeout)
				wg.Done()
			}()
		}
		br.cacheLock.Unlock()
		wg.Wait()
	}
	br.Matrix.Stop()
	if br.cancelBackgroundCtx != nil {
		br.cancelBackgroundCtx()
	}
	if stopNet, ok := br.Network.(StoppableNetwork); ok {
		stopNet.Stop()
	}
	if !br.ExternallyManagedDB {
		err := br.DB.Close()
		if err != nil {
			br.Log.Warn().Err(err).Msg("Failed to close database")
		}
	}
	br.Log.Info().Msg("Shutdown complete")
}
