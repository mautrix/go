// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build cgo && !nocrypto

package matrix

// Ghost devices (encryption.ghost_devices).
//
// Without them, every ghost's message is encrypted with the bridge bot's
// Megolm session. matrix-rust-sdk checks that the session's owner is the
// event's sender, so Element marks each bridged message "The sender of the
// event does not match the owner of the device that sent it". Here each ghost
// gets its own device on first send, with its own Olm account and its own
// cross-signing identity that signs that device, so a client sees an ordinary
// user on an ordinary verified-by-owner device. Stock clients need nothing.
//
// The bot's machine still does everything else: it decrypts what Matrix users
// send, tracks device lists, and answers key requests for its own sessions.
// A ghost's machine only encrypts. In appservice mode, to-device events and
// OTK counts addressed to a ghost device are routed to that ghost's machine;
// in /sync mode ghost devices receive nothing, which only costs key requests
// for ghost-sent sessions (OTKs plus the fallback key cover session setup).
//
// If anything fails for a ghost, its message is encrypted by the bot as
// before: degraded shield, never a lost message.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// ghostAccountPrefix namespaces a ghost's rows in the crypto tables, whose
// account_id is otherwise the bridge ID for the bot.
const ghostAccountPrefix = "ghost:"

// ghostRetryAfter keeps a ghost whose device setup failed on the bot's
// session for a while, instead of retrying on every message.
const ghostRetryAfter = 10 * time.Minute

type ghostEntry struct {
	lock     sync.Mutex
	mach     *crypto.OlmMachine
	failedAt time.Time
}

type ghostMachines struct {
	lock    sync.Mutex
	entries map[id.UserID]*ghostEntry
}

func newGhostMachines() *ghostMachines {
	return &ghostMachines{entries: make(map[id.UserID]*ghostEntry)}
}

func (gm *ghostMachines) entry(userID id.UserID) *ghostEntry {
	gm.lock.Lock()
	defer gm.lock.Unlock()
	e, ok := gm.entries[userID]
	if !ok {
		e = &ghostEntry{}
		gm.entries[userID] = e
	}
	return e
}

// loaded returns the ghost's machine if it is already set up, without
// creating one: inbound to-device traffic must never create devices.
func (gm *ghostMachines) loaded(userID id.UserID) *crypto.OlmMachine {
	gm.lock.Lock()
	e, ok := gm.entries[userID]
	gm.lock.Unlock()
	if !ok {
		return nil
	}
	e.lock.Lock()
	defer e.lock.Unlock()
	return e.mach
}

func (gm *ghostMachines) all() []*crypto.OlmMachine {
	gm.lock.Lock()
	entries := make([]*ghostEntry, 0, len(gm.entries))
	for _, e := range gm.entries {
		entries = append(entries, e)
	}
	gm.lock.Unlock()
	machs := make([]*crypto.OlmMachine, 0, len(entries))
	for _, e := range entries {
		e.lock.Lock()
		if e.mach != nil {
			machs = append(machs, e.mach)
		}
		e.lock.Unlock()
	}
	return machs
}

func (helper *CryptoHelper) ghostDevicesEnabled() bool {
	return helper.bridge.Config.Encryption.GhostDevices
}

// machineFor returns the machine that encrypts as sender: the ghost's own when
// ghost devices are on and sender is a ghost, otherwise the bot's.
// The caller holds helper.lock for reading.
func (helper *CryptoHelper) machineFor(ctx context.Context, sender id.UserID) *crypto.OlmMachine {
	if !helper.ghostDevicesEnabled() || sender == "" || sender == helper.client.UserID {
		return helper.mach
	}
	if _, isGhost := helper.bridge.ParseGhostMXID(sender); !isGhost {
		return helper.mach
	}
	mach, err := helper.ghostMachine(ctx, sender)
	if err != nil {
		zerolog.Ctx(ctx).Warn().Err(err).
			Stringer("ghost_user_id", sender).
			Msg("Ghost has no encryption device, encrypting with the bridge bot's session")
		return helper.mach
	}
	return mach
}

// ghostMachine returns the ghost's machine, setting its device up on first use.
func (helper *CryptoHelper) ghostMachine(ctx context.Context, userID id.UserID) (*crypto.OlmMachine, error) {
	e := helper.ghosts.entry(userID)
	e.lock.Lock()
	defer e.lock.Unlock()
	if e.mach != nil {
		return e.mach, nil
	}
	if !e.failedAt.IsZero() && time.Since(e.failedAt) < ghostRetryAfter {
		return nil, fmt.Errorf("device setup failed %s ago", time.Since(e.failedAt).Round(time.Second))
	}
	mach, err := helper.newGhostMachine(ctx, userID, true)
	if err != nil {
		e.failedAt = time.Now()
		return nil, err
	}
	e.mach = mach
	e.failedAt = time.Time{}
	return mach, nil
}

func (helper *CryptoHelper) ghostStore(userID id.UserID, log zerolog.Logger) *SQLCryptoStore {
	return &SQLCryptoStore{
		SQLCryptoStore: crypto.NewSQLCryptoStore(
			helper.store.DB,
			dbutil.ZeroLogger(log.With().Str("db_section", "crypto").Logger()),
			ghostAccountPrefix+string(userID),
			"",
			[]byte(helper.bridge.Config.Encryption.PickleKey),
		),
		UserID:        helper.store.UserID,
		GhostIDFormat: helper.store.GhostIDFormat,
	}
}

func (helper *CryptoHelper) newGhostMachine(ctx context.Context, userID id.UserID, retryOnLostKeys bool) (*crypto.OlmMachine, error) {
	cfg := helper.bridge.Config.Encryption
	log := helper.log.With().Stringer("ghost_user_id", userID).Logger()
	ctx = log.WithContext(ctx)
	store := helper.ghostStore(userID, log)

	deviceID, err := store.FindDeviceID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to find existing device ID: %w", err)
	}
	client := helper.bridge.AS.NewMautrixClient(userID)
	displayName := fmt.Sprintf("%s bridge", helper.bridge.Bridge.Network.GetName().DisplayName)
	if cfg.MSC4190 {
		err = client.CreateDeviceMSC4190(ctx, deviceID, displayName)
	} else {
		_, err = client.Login(ctx, &mautrix.ReqLogin{
			Type:                     mautrix.AuthTypeAppservice,
			Identifier:               mautrix.UserIdentifier{Type: mautrix.IdentifierTypeUser, User: string(userID)},
			DeviceID:                 deviceID,
			StoreCredentials:         true,
			InitialDeviceDisplayName: displayName,
		})
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create device: %w", err)
	}
	store.DeviceID = client.DeviceID

	mach := crypto.NewOlmMachine(client, &log, store, helper.bridge.StateStore)
	helper.configureMachine(mach)
	if err = mach.Load(ctx); err != nil {
		return nil, fmt.Errorf("failed to load olm account: %w", err)
	}
	if deviceID == "" {
		if err = mach.ShareKeys(ctx, -1); err != nil {
			return nil, fmt.Errorf("failed to upload device keys: %w", err)
		}
		log.Info().Stringer("device_id", client.DeviceID).Msg("Created encryption device for ghost")
	} else if ok, err := helper.deviceKeysOnServer(ctx, client); err != nil {
		return nil, err
	} else if !ok {
		if !retryOnLostKeys {
			return nil, errors.New("device keys missing on server after re-creating the device")
		}
		log.Warn().Stringer("device_id", deviceID).Msg("Ghost device has no keys on server, starting a new device")
		if err = helper.forgetGhostAccount(ctx, userID); err != nil {
			return nil, err
		}
		return helper.newGhostMachine(ctx, userID, false)
	}
	helper.selfSignGhost(ctx, mach, userID)
	return mach, nil
}

func (helper *CryptoHelper) deviceKeysOnServer(ctx context.Context, client *mautrix.Client) (bool, error) {
	resp, err := client.QueryKeys(ctx, &mautrix.ReqQueryKeys{
		DeviceKeys: map[id.UserID]mautrix.DeviceIDList{client.UserID: {client.DeviceID}},
	})
	if err != nil {
		return false, fmt.Errorf("failed to query own device keys: %w", err)
	}
	device, ok := resp.DeviceKeys[client.UserID][client.DeviceID]
	return ok && len(device.Keys) > 0, nil
}

// forgetGhostAccount drops one ghost's Olm account and sessions, so its next
// setup makes a fresh device. Inbound sessions it received are kept.
func (helper *CryptoHelper) forgetGhostAccount(ctx context.Context, userID id.UserID) error {
	accountID := ghostAccountPrefix + string(userID)
	for _, table := range []string{"crypto_olm_session", "crypto_megolm_outbound_session", "crypto_account"} {
		if _, err := helper.store.DB.Exec(ctx, "DELETE FROM "+table+" WHERE account_id=$1", accountID); err != nil {
			return fmt.Errorf("failed to clear %s for ghost: %w", table, err)
		}
	}
	return nil
}

func ghostRecoveryKeyKey(userID id.UserID) database.Key {
	return database.Key("ghost_recovery_key:" + string(userID))
}

// selfSignGhost gives the ghost a cross-signing identity that signs its device.
// A failure leaves the device unverified by its owner, which clients show as a
// milder warning than a mismatched sender, so it is logged and not fatal.
func (helper *CryptoHelper) selfSignGhost(ctx context.Context, mach *crypto.OlmMachine, userID id.UserID) {
	log := zerolog.Ctx(ctx)
	kv := helper.bridge.Bridge.DB.KV
	hasKeys, isVerified, err := mach.GetOwnVerificationStatus(ctx)
	if err != nil {
		log.Err(err).Msg("Failed to check ghost verification status")
		return
	}
	if !hasKeys {
		recoveryKey, err := mach.GenerateAndVerifyWithRecoveryKey(ctx)
		if recoveryKey != "" {
			kv.Set(ctx, ghostRecoveryKeyKey(userID), recoveryKey)
		}
		if err != nil {
			log.Err(err).Msg("Failed to generate cross-signing keys for ghost")
			return
		}
		log.Info().Msg("Generated cross-signing keys for ghost and signed its device")
	} else if !isVerified {
		recoveryKey := kv.Get(ctx, ghostRecoveryKeyKey(userID))
		if recoveryKey == "" {
			log.Warn().Msg("Ghost has cross-signing keys on the server but no recovery key in the database, its device stays unverified")
			return
		}
		if err = mach.VerifyWithRecoveryKey(ctx, recoveryKey); err != nil {
			log.Err(err).Msg("Failed to sign ghost device with its recovery key")
			return
		}
		log.Info().Msg("Signed ghost device with its existing recovery key")
	}
}

// loadGhostMachines sets up every ghost that already has a device, so
// to-device traffic for it is routed after a restart. New ghosts are set up
// on their first send instead.
func (helper *CryptoHelper) loadGhostMachines(ctx context.Context) {
	rows, err := helper.store.DB.Query(ctx, "SELECT account_id FROM crypto_account WHERE account_id LIKE $1", ghostAccountPrefix+"%")
	accountIDs, err := dbutil.NewRowIterWithError(rows, dbutil.ScanSingleColumn[string], err).AsList()
	if err != nil {
		helper.log.Err(err).Msg("Failed to list ghost encryption devices")
		return
	}
	for _, accountID := range accountIDs {
		userID := id.UserID(strings.TrimPrefix(accountID, ghostAccountPrefix))
		if _, err = helper.ghostMachine(ctx, userID); err != nil {
			helper.log.Warn().Err(err).Stringer("ghost_user_id", userID).Msg("Failed to load ghost encryption device")
		}
	}
	helper.log.Debug().Int("count", len(accountIDs)).Msg("Loaded ghost encryption devices")
}

// addRoutedAppserviceListener replaces OlmMachine.AddAppserviceListener when
// ghost devices are on: one set of listeners that hands each to-device event
// and OTK count to the machine of the device it is addressed to.
func (helper *CryptoHelper) addRoutedAppserviceListener(ep crypto.ASEventProcessor) {
	for _, evtType := range []event.Type{
		event.ToDeviceEncrypted,
		event.ToDeviceRoomKeyRequest,
		event.ToDeviceRoomKeyWithheld,
		event.ToDeviceBeeperRoomKeyAck,
		event.ToDeviceOrgMatrixRoomKeyWithheld,
		event.ToDeviceVerificationRequest,
		event.ToDeviceVerificationStart,
		event.ToDeviceVerificationAccept,
		event.ToDeviceVerificationKey,
		event.ToDeviceVerificationMAC,
		event.ToDeviceVerificationCancel,
	} {
		ep.On(evtType, helper.routeToDevice)
	}
	ep.OnOTK(helper.routeOTKCounts)
	ep.OnDeviceList(helper.handleDeviceLists)
}

func (helper *CryptoHelper) routedMachine(userID id.UserID) *crypto.OlmMachine {
	if userID == "" || userID == helper.client.UserID {
		return helper.mach
	}
	return helper.ghosts.loaded(userID)
}

func (helper *CryptoHelper) routeToDevice(ctx context.Context, evt *event.Event) {
	helper.lock.RLock()
	defer helper.lock.RUnlock()
	if mach := helper.routedMachine(evt.ToUserID); mach != nil {
		mach.HandleToDeviceEvent(ctx, evt)
	}
}

func (helper *CryptoHelper) routeOTKCounts(ctx context.Context, otk *mautrix.OTKCount) {
	helper.lock.RLock()
	defer helper.lock.RUnlock()
	if mach := helper.routedMachine(otk.UserID); mach != nil {
		mach.HandleOTKCounts(ctx, otk)
	}
}

func (helper *CryptoHelper) handleDeviceLists(ctx context.Context, lists *mautrix.DeviceLists, since string) {
	helper.lock.RLock()
	defer helper.lock.RUnlock()
	helper.mach.HandleDeviceLists(ctx, lists, since)
	helper.rotateGhostSessions(ctx, lists.Changed)
}

// rotateGhostSessions does for ghost machines what the bot's machine does for
// itself on a device change: drop the outbound session in rooms shared with
// that user, so the next message is shared with their new device too.
// The bot's machine is the only one that fetches device lists, so ghost
// machines never see the change themselves.
func (helper *CryptoHelper) rotateGhostSessions(ctx context.Context, changed []id.UserID) {
	if !helper.ghostDevicesEnabled() || helper.bridge.Config.Encryption.Rotation.DisableDeviceChangeKeyRotation || len(changed) == 0 {
		return
	}
	machs := helper.ghosts.all()
	if len(machs) == 0 {
		return
	}
	for _, userID := range changed {
		if userID == helper.client.UserID {
			continue
		} else if _, isGhost := helper.bridge.ParseGhostMXID(userID); isGhost {
			continue
		}
		for _, mach := range machs {
			mach.OnDevicesChanged(ctx, userID)
		}
	}
}
