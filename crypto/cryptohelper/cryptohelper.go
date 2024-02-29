// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package cryptohelper

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"

	"github.com/element-hq/mautrix-go"
	"github.com/element-hq/mautrix-go/crypto"
	"github.com/element-hq/mautrix-go/event"
	"github.com/element-hq/mautrix-go/id"
	"github.com/element-hq/mautrix-go/sqlstatestore"
)

type CryptoHelper struct {
	client    *mautrix.Client
	mach      *crypto.OlmMachine
	log       zerolog.Logger
	lock      sync.RWMutex
	pickleKey []byte

	managedStateStore    *sqlstatestore.SQLStateStore
	unmanagedCryptoStore crypto.Store
	dbForManagedStores   *dbutil.Database

	DecryptErrorCallback func(*event.Event, error)

	LoginAs *mautrix.ReqLogin

	DBAccountID string
}

var _ mautrix.CryptoHelper = (*CryptoHelper)(nil)

// NewCryptoHelper creates a struct that helps a mautrix client struct with Matrix e2ee operations.
//
// The client and pickle key are always required. Additionally, you must either:
// - Provide a crypto.Store here and set a StateStore in the client, or
// - Provide a dbutil.Database here to automatically create missing stores.
// - Provide a string here to use it as a path to a SQLite database, and then automatically create missing stores.
//
// The same database may be shared across multiple clients, but note that doing that will allow all clients access to
// decryption keys received by any one of the clients. For that reason, the pickle key must also be same for all clients
// using the same database.
func NewCryptoHelper(cli *mautrix.Client, pickleKey []byte, store any) (*CryptoHelper, error) {
	if len(pickleKey) == 0 {
		return nil, fmt.Errorf("pickle key must be provided")
	}
	_, isExtensible := cli.Syncer.(mautrix.ExtensibleSyncer)
	if !isExtensible {
		return nil, fmt.Errorf("the client syncer must implement ExtensibleSyncer")
	}

	var managedStateStore *sqlstatestore.SQLStateStore
	var dbForManagedStores *dbutil.Database
	var unmanagedCryptoStore crypto.Store
	switch typedStore := store.(type) {
	case crypto.Store:
		if cli.StateStore == nil {
			return nil, fmt.Errorf("when passing a crypto.Store to NewCryptoHelper, the client must have a state store set beforehand")
		} else if _, isCryptoCompatible := cli.StateStore.(crypto.StateStore); !isCryptoCompatible {
			return nil, fmt.Errorf("the client state store must implement crypto.StateStore")
		}
		unmanagedCryptoStore = typedStore
	case string:
		db, err := dbutil.NewWithDialect(typedStore, "sqlite3")
		if err != nil {
			return nil, err
		}
		dbForManagedStores = db
	case *dbutil.Database:
		dbForManagedStores = typedStore
	default:
		return nil, fmt.Errorf("you must pass a *dbutil.Database or *crypto.StateStore to NewCryptoHelper")
	}
	log := cli.Log.With().Str("component", "crypto").Logger()
	if cli.StateStore == nil && dbForManagedStores != nil {
		managedStateStore = sqlstatestore.NewSQLStateStore(dbForManagedStores, dbutil.ZeroLogger(log.With().Str("db_section", "matrix_state").Logger()), false)
		cli.StateStore = managedStateStore
	} else if _, isCryptoCompatible := cli.StateStore.(crypto.StateStore); !isCryptoCompatible {
		return nil, fmt.Errorf("the client state store must implement crypto.StateStore")
	}

	return &CryptoHelper{
		client:    cli,
		log:       log,
		pickleKey: pickleKey,

		unmanagedCryptoStore: unmanagedCryptoStore,
		managedStateStore:    managedStateStore,
		dbForManagedStores:   dbForManagedStores,

		DecryptErrorCallback: func(_ *event.Event, _ error) {},
	}, nil
}

func (helper *CryptoHelper) Init(ctx context.Context) error {
	if helper == nil {
		return fmt.Errorf("crypto helper is nil")
	}
	syncer, ok := helper.client.Syncer.(mautrix.ExtensibleSyncer)
	if !ok {
		return fmt.Errorf("the client syncer must implement ExtensibleSyncer")
	}

	var stateStore crypto.StateStore
	if helper.managedStateStore != nil {
		err := helper.managedStateStore.Upgrade(ctx)
		if err != nil {
			return fmt.Errorf("failed to upgrade client state store: %w", err)
		}
		stateStore = helper.managedStateStore
	} else {
		stateStore = helper.client.StateStore.(crypto.StateStore)
	}
	var cryptoStore crypto.Store
	if helper.unmanagedCryptoStore == nil {
		managedCryptoStore := crypto.NewSQLCryptoStore(helper.dbForManagedStores, dbutil.ZeroLogger(helper.log.With().Str("db_section", "crypto").Logger()), helper.DBAccountID, helper.client.DeviceID, helper.pickleKey)
		if helper.client.Store == nil {
			helper.client.Store = managedCryptoStore
		} else if _, isMemory := helper.client.Store.(*mautrix.MemorySyncStore); isMemory {
			helper.client.Store = managedCryptoStore
		}
		err := managedCryptoStore.DB.Upgrade(ctx)
		if err != nil {
			return fmt.Errorf("failed to upgrade crypto state store: %w", err)
		}
		storedDeviceID, err := managedCryptoStore.FindDeviceID(ctx)
		if err != nil {
			return fmt.Errorf("failed to find existing device ID: %w", err)
		}
		if helper.LoginAs != nil {
			if storedDeviceID != "" {
				helper.LoginAs.DeviceID = storedDeviceID
			}
			helper.LoginAs.StoreCredentials = true
			helper.log.Debug().
				Str("username", helper.LoginAs.Identifier.User).
				Str("device_id", helper.LoginAs.DeviceID.String()).
				Msg("Logging in")
			_, err = helper.client.Login(ctx, helper.LoginAs)
			if err != nil {
				return err
			}
			if storedDeviceID == "" {
				managedCryptoStore.DeviceID = helper.client.DeviceID
			}
		} else if storedDeviceID != "" && storedDeviceID != helper.client.DeviceID {
			return fmt.Errorf("mismatching device ID in client and crypto store (%q != %q)", storedDeviceID, helper.client.DeviceID)
		}
		cryptoStore = managedCryptoStore
	} else {
		if helper.LoginAs != nil {
			return fmt.Errorf("LoginAs can only be used with a managed crypto store")
		}
		cryptoStore = helper.unmanagedCryptoStore
	}
	if helper.client.DeviceID == "" || helper.client.UserID == "" {
		return fmt.Errorf("the client must be logged in")
	}
	helper.mach = crypto.NewOlmMachine(helper.client, &helper.log, cryptoStore, stateStore)
	err := helper.mach.Load(ctx)
	if err != nil {
		return fmt.Errorf("failed to load olm account: %w", err)
	} else if err = helper.verifyDeviceKeysOnServer(ctx); err != nil {
		return err
	}

	syncer.OnSync(helper.mach.ProcessSyncResponse)
	syncer.OnEventType(event.StateMember, helper.mach.HandleMemberEvent)
	if _, ok = helper.client.Syncer.(mautrix.DispatchableSyncer); ok {
		syncer.OnEventType(event.EventEncrypted, helper.HandleEncrypted)
	} else {
		helper.log.Warn().Msg("Client syncer does not implement DispatchableSyncer. Events will not be decrypted automatically.")
	}
	if helper.managedStateStore != nil {
		syncer.OnEvent(helper.client.StateStoreSyncHandler)
	}
	return nil
}

func (helper *CryptoHelper) Close() error {
	if helper != nil && helper.dbForManagedStores != nil {
		err := helper.dbForManagedStores.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (helper *CryptoHelper) Machine() *crypto.OlmMachine {
	if helper == nil || helper.mach == nil {
		panic("Machine() called before initing CryptoHelper")
	}
	return helper.mach
}

func (helper *CryptoHelper) verifyDeviceKeysOnServer(ctx context.Context) error {
	helper.log.Debug().Msg("Making sure our device has the expected keys on the server")
	resp, err := helper.client.QueryKeys(ctx, &mautrix.ReqQueryKeys{
		DeviceKeys: map[id.UserID]mautrix.DeviceIDList{
			helper.client.UserID: {helper.client.DeviceID},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to query own keys to make sure device is properly configured: %w", err)
	}
	ownID := helper.mach.OwnIdentity()
	isShared := helper.mach.GetAccount().Shared
	device, ok := resp.DeviceKeys[helper.client.UserID][helper.client.DeviceID]
	if !ok || len(device.Keys) == 0 {
		if isShared {
			return fmt.Errorf("olm account is marked as shared, keys seem to have disappeared from the server")
		} else {
			helper.log.Debug().Msg("Olm account not shared and keys not on server, so device is probably fine")
			return nil
		}
	} else if !isShared {
		return fmt.Errorf("olm account is not marked as shared, but there are keys on the server")
	} else if ed := device.Keys.GetEd25519(helper.client.DeviceID); ownID.SigningKey != ed {
		return fmt.Errorf("mismatching identity key on server (%q != %q)", ownID.SigningKey, ed)
	}
	if !isShared {
		helper.log.Debug().Msg("Olm account not marked as shared, but keys on server match?")
	} else {
		helper.log.Debug().Msg("Olm account marked as shared and keys on server match, device is fine")
	}
	return nil
}

var NoSessionFound = crypto.NoSessionFound

const initialSessionWaitTimeout = 3 * time.Second
const extendedSessionWaitTimeout = 22 * time.Second

func (helper *CryptoHelper) HandleEncrypted(ctx context.Context, evt *event.Event) {
	if helper == nil {
		return
	}
	content := evt.Content.AsEncrypted()
	// TODO use context log instead of helper?
	log := helper.log.With().
		Str("event_id", evt.ID.String()).
		Str("session_id", content.SessionID.String()).
		Logger()
	log.Debug().Msg("Decrypting received event")
	ctx = log.WithContext(ctx)

	decrypted, err := helper.Decrypt(ctx, evt)
	if errors.Is(err, NoSessionFound) {
		log.Debug().
			Int("wait_seconds", int(initialSessionWaitTimeout.Seconds())).
			Msg("Couldn't find session, waiting for keys to arrive...")
		if helper.mach.WaitForSession(ctx, evt.RoomID, content.SenderKey, content.SessionID, initialSessionWaitTimeout) {
			log.Debug().Msg("Got keys after waiting, trying to decrypt event again")
			decrypted, err = helper.Decrypt(ctx, evt)
		} else {
			go helper.waitLongerForSession(ctx, log, evt)
			return
		}
	}
	if err != nil {
		log.Warn().Err(err).Msg("Failed to decrypt event")
		helper.DecryptErrorCallback(evt, err)
		return
	}
	helper.postDecrypt(ctx, decrypted)
}

func (helper *CryptoHelper) postDecrypt(ctx context.Context, decrypted *event.Event) {
	decrypted.Mautrix.EventSource |= event.SourceDecrypted
	helper.client.Syncer.(mautrix.DispatchableSyncer).Dispatch(ctx, decrypted)
}

func (helper *CryptoHelper) RequestSession(ctx context.Context, roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID, userID id.UserID, deviceID id.DeviceID) {
	if helper == nil {
		return
	}
	helper.lock.RLock()
	defer helper.lock.RUnlock()
	if deviceID == "" {
		deviceID = "*"
	}
	// TODO get log from context
	log := helper.log.With().
		Str("session_id", sessionID.String()).
		Str("user_id", userID.String()).
		Str("device_id", deviceID.String()).
		Str("room_id", roomID.String()).
		Logger()
	err := helper.mach.SendRoomKeyRequest(ctx, roomID, senderKey, sessionID, "", map[id.UserID][]id.DeviceID{
		userID:               {deviceID},
		helper.client.UserID: {"*"},
	})
	if err != nil {
		log.Warn().Err(err).Msg("Failed to send key request")
	} else {
		log.Debug().Msg("Sent key request")
	}
}

func (helper *CryptoHelper) waitLongerForSession(ctx context.Context, log zerolog.Logger, evt *event.Event) {
	content := evt.Content.AsEncrypted()
	log.Debug().Int("wait_seconds", int(extendedSessionWaitTimeout.Seconds())).Msg("Couldn't find session, requesting keys and waiting longer...")

	go helper.RequestSession(context.TODO(), evt.RoomID, content.SenderKey, content.SessionID, evt.Sender, content.DeviceID)

	if !helper.mach.WaitForSession(ctx, evt.RoomID, content.SenderKey, content.SessionID, extendedSessionWaitTimeout) {
		log.Debug().Msg("Didn't get session, giving up")
		helper.DecryptErrorCallback(evt, NoSessionFound)
		return
	}

	log.Debug().Msg("Got keys after waiting longer, trying to decrypt event again")
	decrypted, err := helper.Decrypt(ctx, evt)
	if err != nil {
		log.Error().Err(err).Msg("Failed to decrypt event")
		helper.DecryptErrorCallback(evt, err)
		return
	}

	helper.postDecrypt(ctx, decrypted)
}

func (helper *CryptoHelper) WaitForSession(ctx context.Context, roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID, timeout time.Duration) bool {
	if helper == nil {
		return false
	}
	helper.lock.RLock()
	defer helper.lock.RUnlock()
	return helper.mach.WaitForSession(ctx, roomID, senderKey, sessionID, timeout)
}

func (helper *CryptoHelper) Decrypt(ctx context.Context, evt *event.Event) (*event.Event, error) {
	if helper == nil {
		return nil, fmt.Errorf("crypto helper is nil")
	}
	return helper.mach.DecryptMegolmEvent(ctx, evt)
}

func (helper *CryptoHelper) Encrypt(ctx context.Context, roomID id.RoomID, evtType event.Type, content any) (encrypted *event.EncryptedEventContent, err error) {
	if helper == nil {
		return nil, fmt.Errorf("crypto helper is nil")
	}
	helper.lock.RLock()
	defer helper.lock.RUnlock()
	encrypted, err = helper.mach.EncryptMegolmEvent(ctx, roomID, evtType, content)
	if err != nil {
		if !errors.Is(err, crypto.SessionExpired) && err != crypto.NoGroupSession && !errors.Is(err, crypto.SessionNotShared) {
			return
		}
		helper.log.Debug().
			Err(err).
			Str("room_id", roomID.String()).
			Msg("Got session error while encrypting event, sharing group session and trying again")
		var users []id.UserID
		users, err = helper.client.StateStore.GetRoomJoinedOrInvitedMembers(ctx, roomID)
		if err != nil {
			err = fmt.Errorf("failed to get room member list: %w", err)
		} else if err = helper.mach.ShareGroupSession(ctx, roomID, users); err != nil {
			err = fmt.Errorf("failed to share group session: %w", err)
		} else if encrypted, err = helper.mach.EncryptMegolmEvent(ctx, roomID, evtType, content); err != nil {
			err = fmt.Errorf("failed to encrypt event after re-sharing group session: %w", err)
		}
	}
	return
}
