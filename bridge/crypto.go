// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build cgo && !nocrypto

package bridge

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridge/bridgeconfig"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/sqlstatestore"
	"maunium.net/go/mautrix/util/dbutil"
)

var _ crypto.StateStore = (*sqlstatestore.SQLStateStore)(nil)

var NoSessionFound = crypto.NoSessionFound
var UnknownMessageIndex = olm.UnknownMessageIndex

type CryptoHelper struct {
	bridge *Bridge
	client *mautrix.Client
	mach   *crypto.OlmMachine
	store  *SQLCryptoStore
	log    *zerolog.Logger

	lock       sync.RWMutex
	syncDone   sync.WaitGroup
	cancelSync func()
}

func NewCryptoHelper(bridge *Bridge) Crypto {
	if !bridge.Config.Bridge.GetEncryptionConfig().Allow {
		bridge.ZLog.Debug().Msg("Bridge built with end-to-bridge encryption, but disabled in config")
		return nil
	}
	log := bridge.ZLog.With().Str("component", "crypto").Logger()
	return &CryptoHelper{
		bridge: bridge,
		log:    &log,
	}
}

func (helper *CryptoHelper) Init() error {
	if len(helper.bridge.CryptoPickleKey) == 0 {
		panic("CryptoPickleKey not set")
	}
	helper.log.Debug().Msg("Initializing end-to-bridge encryption...")

	helper.store = NewSQLCryptoStore(
		helper.bridge.DB,
		dbutil.ZeroLogger(helper.bridge.ZLog.With().Str("db_section", "crypto").Logger()),
		helper.bridge.AS.BotMXID(),
		fmt.Sprintf("@%s:%s", helper.bridge.Config.Bridge.FormatUsername("%"), helper.bridge.AS.HomeserverDomain),
		helper.bridge.CryptoPickleKey,
	)

	err := helper.store.DB.Upgrade()
	if err != nil {
		helper.bridge.LogDBUpgradeErrorAndExit("crypto", err)
	}

	var isExistingDevice bool
	helper.client, isExistingDevice, err = helper.loginBot()
	if err != nil {
		return err
	}

	helper.log.Debug().
		Str("device_id", helper.client.DeviceID.String()).
		Msg("Logged in as bridge bot")
	stateStore := &cryptoStateStore{helper.bridge}
	helper.mach = crypto.NewOlmMachine(helper.client, helper.log, helper.store, stateStore)
	helper.mach.AllowKeyShare = helper.allowKeyShare
	helper.mach.SendKeysMinTrust = helper.bridge.Config.Bridge.GetEncryptionConfig().VerificationLevels.Receive
	helper.mach.PlaintextMentions = helper.bridge.Config.Bridge.GetEncryptionConfig().PlaintextMentions

	helper.client.Syncer = &cryptoSyncer{helper.mach}
	helper.client.Store = helper.store

	err = helper.mach.Load()
	if err != nil {
		return err
	}
	if isExistingDevice {
		helper.verifyKeysAreOnServer()
	}
	return nil
}

func (helper *CryptoHelper) allowKeyShare(ctx context.Context, device *id.Device, info event.RequestedKeyInfo) *crypto.KeyShareRejection {
	cfg := helper.bridge.Config.Bridge.GetEncryptionConfig()
	if !cfg.AllowKeySharing {
		return &crypto.KeyShareRejectNoResponse
	} else if device.Trust == id.TrustStateBlacklisted {
		return &crypto.KeyShareRejectBlacklisted
	} else if trustState := helper.mach.ResolveTrust(device); trustState >= cfg.VerificationLevels.Share {
		portal := helper.bridge.Child.GetIPortal(info.RoomID)
		if portal == nil {
			zerolog.Ctx(ctx).Debug().Msg("Rejecting key request: room is not a portal")
			return &crypto.KeyShareRejection{Code: event.RoomKeyWithheldUnavailable, Reason: "Requested room is not a portal room"}
		}
		user := helper.bridge.Child.GetIUser(device.UserID, true)
		// FIXME reimplement IsInPortal
		if user.GetPermissionLevel() < bridgeconfig.PermissionLevelAdmin /*&& !user.IsInPortal(portal.Key)*/ {
			zerolog.Ctx(ctx).Debug().Msg("Rejecting key request: user is not in portal")
			return &crypto.KeyShareRejection{Code: event.RoomKeyWithheldUnauthorized, Reason: "You're not in that portal"}
		}
		zerolog.Ctx(ctx).Debug().Msg("Accepting key request")
		return nil
	} else {
		return &crypto.KeyShareRejectUnverified
	}
}

func (helper *CryptoHelper) loginBot() (*mautrix.Client, bool, error) {
	deviceID := helper.store.FindDeviceID()
	if len(deviceID) > 0 {
		helper.log.Debug().Str("device_id", deviceID.String()).Msg("Found existing device ID for bot in database")
	}
	client, err := mautrix.NewClient(helper.bridge.AS.HomeserverURL, "", "")
	if err != nil {
		return nil, deviceID != "", fmt.Errorf("failed to initialize client: %w", err)
	}
	client.StateStore = helper.bridge.AS.StateStore
	client.Log = helper.log.With().Str("as_user_id", helper.bridge.AS.BotMXID().String()).Logger()
	client.Client = helper.bridge.AS.HTTPClient
	client.DefaultHTTPRetries = helper.bridge.AS.DefaultHTTPRetries
	flows, err := client.GetLoginFlows()
	if err != nil {
		return nil, deviceID != "", fmt.Errorf("failed to get supported login flows: %w", err)
	} else if !flows.HasFlow(mautrix.AuthTypeAppservice) {
		return nil, deviceID != "", fmt.Errorf("homeserver does not support appservice login")
	}
	// We set the API token to the AS token here to authenticate the appservice login
	// It'll get overridden after the login
	client.AccessToken = helper.bridge.AS.Registration.AppToken
	resp, err := client.Login(&mautrix.ReqLogin{
		Type: mautrix.AuthTypeAppservice,
		Identifier: mautrix.UserIdentifier{
			Type: mautrix.IdentifierTypeUser,
			User: string(helper.bridge.AS.BotMXID()),
		},
		DeviceID:         deviceID,
		StoreCredentials: true,

		InitialDeviceDisplayName: fmt.Sprintf("%s bridge", helper.bridge.ProtocolName),
	})
	if err != nil {
		return nil, deviceID != "", fmt.Errorf("failed to log in as bridge bot: %w", err)
	}
	helper.store.DeviceID = resp.DeviceID
	return client, deviceID != "", nil
}

func (helper *CryptoHelper) verifyKeysAreOnServer() {
	helper.log.Debug().Msg("Making sure keys are still on server")
	resp, err := helper.client.QueryKeys(&mautrix.ReqQueryKeys{
		DeviceKeys: map[id.UserID]mautrix.DeviceIDList{
			helper.client.UserID: {helper.client.DeviceID},
		},
	})
	if err != nil {
		helper.log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Failed to query own keys to make sure device still exists")
		os.Exit(33)
	}
	device, ok := resp.DeviceKeys[helper.client.UserID][helper.client.DeviceID]
	if ok && len(device.Keys) > 0 {
		return
	}
	helper.log.Warn().Msg("Existing device doesn't have keys on server, resetting crypto")
	helper.Reset(false)
}

func (helper *CryptoHelper) Start() {
	if helper.bridge.Config.Bridge.GetEncryptionConfig().Appservice {
		helper.log.Debug().Msg("End-to-bridge encryption is in appservice mode, registering event listeners and not starting syncer")
		helper.bridge.AS.Registration.EphemeralEvents = true
		helper.mach.AddAppserviceListener(helper.bridge.EventProcessor)
		return
	}
	helper.syncDone.Add(1)
	defer helper.syncDone.Done()
	helper.log.Debug().Msg("Starting syncer for receiving to-device messages")
	var ctx context.Context
	ctx, helper.cancelSync = context.WithCancel(context.Background())
	err := helper.client.SyncWithContext(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		helper.log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Fatal error syncing")
		os.Exit(51)
	} else {
		helper.log.Info().Msg("Bridge bot to-device syncer stopped without error")
	}
}

func (helper *CryptoHelper) Stop() {
	helper.log.Debug().Msg("CryptoHelper.Stop() called, stopping bridge bot sync")
	helper.client.StopSync()
	if helper.cancelSync != nil {
		helper.cancelSync()
	}
	helper.syncDone.Wait()
}

func (helper *CryptoHelper) clearDatabase() {
	_, err := helper.store.DB.Exec("DELETE FROM crypto_account")
	if err != nil {
		helper.log.Warn().Err(err).Msg("Failed to clear crypto_account table")
	}
	_, err = helper.store.DB.Exec("DELETE FROM crypto_olm_session")
	if err != nil {
		helper.log.Warn().Err(err).Msg("Failed to clear crypto_olm_session table")
	}
	_, err = helper.store.DB.Exec("DELETE FROM crypto_megolm_outbound_session")
	if err != nil {
		helper.log.Warn().Err(err).Msg("Failed to clear crypto_megolm_outbound_session table")
	}
	//_, _ = helper.store.DB.Exec("DELETE FROM crypto_device")
	//_, _ = helper.store.DB.Exec("DELETE FROM crypto_tracked_user")
	//_, _ = helper.store.DB.Exec("DELETE FROM crypto_cross_signing_keys")
	//_, _ = helper.store.DB.Exec("DELETE FROM crypto_cross_signing_signatures")
}

func (helper *CryptoHelper) Reset(startAfterReset bool) {
	helper.lock.Lock()
	defer helper.lock.Unlock()
	helper.log.Info().Msg("Resetting end-to-bridge encryption device")
	helper.Stop()
	helper.log.Debug().Msg("Crypto syncer stopped, clearing database")
	helper.clearDatabase()
	helper.log.Debug().Msg("Crypto database cleared, logging out of all sessions")
	_, err := helper.client.LogoutAll()
	if err != nil {
		helper.log.Warn().Err(err).Msg("Failed to log out all devices")
	}
	helper.client = nil
	helper.store = nil
	helper.mach = nil
	err = helper.Init()
	if err != nil {
		helper.log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Error reinitializing end-to-bridge encryption")
		os.Exit(50)
	}
	helper.log.Info().Msg("End-to-bridge encryption successfully reset")
	if startAfterReset {
		go helper.Start()
	}
}

func (helper *CryptoHelper) Client() *mautrix.Client {
	return helper.client
}

func (helper *CryptoHelper) Decrypt(evt *event.Event) (*event.Event, error) {
	return helper.mach.DecryptMegolmEvent(context.TODO(), evt)
}

func (helper *CryptoHelper) Encrypt(roomID id.RoomID, evtType event.Type, content *event.Content) (err error) {
	helper.lock.RLock()
	defer helper.lock.RUnlock()
	var encrypted *event.EncryptedEventContent
	ctx := context.TODO()
	encrypted, err = helper.mach.EncryptMegolmEvent(ctx, roomID, evtType, content)
	if err != nil {
		if err != crypto.SessionExpired && err != crypto.SessionNotShared && err != crypto.NoGroupSession {
			return
		}
		helper.log.Debug().Err(err).
			Str("room_id", roomID.String()).
			Msg("Got error while encrypting event for room, sharing group session and trying again...")
		var users []id.UserID
		users, err = helper.store.GetRoomJoinedOrInvitedMembers(roomID)
		if err != nil {
			err = fmt.Errorf("failed to get room member list: %w", err)
		} else if err = helper.mach.ShareGroupSession(ctx, roomID, users); err != nil {
			err = fmt.Errorf("failed to share group session: %w", err)
		} else if encrypted, err = helper.mach.EncryptMegolmEvent(ctx, roomID, evtType, content); err != nil {
			err = fmt.Errorf("failed to encrypt event after re-sharing group session: %w", err)
		}
	}
	if encrypted != nil {
		content.Parsed = encrypted
		content.Raw = nil
	}
	return
}

func (helper *CryptoHelper) WaitForSession(roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID, timeout time.Duration) bool {
	helper.lock.RLock()
	defer helper.lock.RUnlock()
	return helper.mach.WaitForSession(roomID, senderKey, sessionID, timeout)
}

func (helper *CryptoHelper) RequestSession(roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID, userID id.UserID, deviceID id.DeviceID) {
	helper.lock.RLock()
	defer helper.lock.RUnlock()
	if deviceID == "" {
		deviceID = "*"
	}
	err := helper.mach.SendRoomKeyRequest(roomID, senderKey, sessionID, "", map[id.UserID][]id.DeviceID{userID: {deviceID}})
	if err != nil {
		helper.log.Warn().Err(err).
			Str("user_id", userID.String()).
			Str("device_id", deviceID.String()).
			Str("session_id", sessionID.String()).
			Str("room_id", roomID.String()).
			Msg("Failed to send key request")
	} else {
		helper.log.Debug().
			Str("user_id", userID.String()).
			Str("device_id", deviceID.String()).
			Str("session_id", sessionID.String()).
			Str("room_id", roomID.String()).
			Msg("Sent key request")
	}
}

func (helper *CryptoHelper) ResetSession(roomID id.RoomID) {
	helper.lock.RLock()
	defer helper.lock.RUnlock()
	err := helper.mach.CryptoStore.RemoveOutboundGroupSession(roomID)
	if err != nil {
		helper.log.Debug().Err(err).
			Str("room_id", roomID.String()).
			Msg("Error manually removing outbound group session in room")
	}
}

func (helper *CryptoHelper) HandleMemberEvent(evt *event.Event) {
	helper.lock.RLock()
	defer helper.lock.RUnlock()
	helper.mach.HandleMemberEvent(0, evt)
}

type cryptoSyncer struct {
	*crypto.OlmMachine
}

func (syncer *cryptoSyncer) ProcessResponse(resp *mautrix.RespSync, since string) error {
	done := make(chan struct{})
	go func() {
		defer func() {
			if err := recover(); err != nil {
				syncer.Log.Error().
					Str("since", since).
					Interface("error", err).
					Str("stack", string(debug.Stack())).
					Msg("Processing sync response panicked")
			}
			done <- struct{}{}
		}()
		syncer.Log.Trace().Str("since", since).Msg("Starting sync response handling")
		syncer.ProcessSyncResponse(resp, since)
		syncer.Log.Trace().Str("since", since).Msg("Successfully handled sync response")
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		syncer.Log.Warn().Str("since", since).Msg("Handling sync response is taking unusually long")
	}
	return nil
}

func (syncer *cryptoSyncer) OnFailedSync(_ *mautrix.RespSync, err error) (time.Duration, error) {
	if errors.Is(err, mautrix.MUnknownToken) {
		return 0, err
	}
	syncer.Log.Error().Err(err).Msg("Error /syncing, waiting 10 seconds")
	return 10 * time.Second, nil
}

func (syncer *cryptoSyncer) GetFilterJSON(_ id.UserID) *mautrix.Filter {
	everything := []event.Type{{Type: "*"}}
	return &mautrix.Filter{
		Presence:    mautrix.FilterPart{NotTypes: everything},
		AccountData: mautrix.FilterPart{NotTypes: everything},
		Room: mautrix.RoomFilter{
			IncludeLeave: false,
			Ephemeral:    mautrix.FilterPart{NotTypes: everything},
			AccountData:  mautrix.FilterPart{NotTypes: everything},
			State:        mautrix.FilterPart{NotTypes: everything},
			Timeline:     mautrix.FilterPart{NotTypes: everything},
		},
	}
}

type cryptoStateStore struct {
	bridge *Bridge
}

var _ crypto.StateStore = (*cryptoStateStore)(nil)

func (c *cryptoStateStore) IsEncrypted(id id.RoomID) bool {
	portal := c.bridge.Child.GetIPortal(id)
	if portal != nil {
		return portal.IsEncrypted()
	}
	return c.bridge.StateStore.IsEncrypted(id)
}

func (c *cryptoStateStore) FindSharedRooms(id id.UserID) []id.RoomID {
	return c.bridge.StateStore.FindSharedRooms(id)
}

func (c *cryptoStateStore) GetEncryptionEvent(id id.RoomID) *event.EncryptionEventContent {
	return c.bridge.StateStore.GetEncryptionEvent(id)
}
