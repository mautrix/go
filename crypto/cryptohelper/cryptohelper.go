// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package cryptohelper

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/sqlstatestore"
	"maunium.net/go/mautrix/util/dbutil"
)

type CryptoHelper struct {
	client    *mautrix.Client
	mach      *crypto.OlmMachine
	log       mautrix.WarnLogger
	lock      sync.RWMutex
	pickleKey []byte

	managedStateStore    *sqlstatestore.SQLStateStore
	unmanagedCryptoStore crypto.Store
	dbForManagedStores   *dbutil.Database

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
	if cli.StateStore == nil && dbForManagedStores != nil {
		// TODO log
		managedStateStore = sqlstatestore.NewSQLStateStore(dbForManagedStores, nil)
		cli.StateStore = managedStateStore
	} else if _, isCryptoCompatible := cli.StateStore.(crypto.StateStore); !isCryptoCompatible {
		return nil, fmt.Errorf("the client state store must implement crypto.StateStore")
	}

	return &CryptoHelper{
		client:    cli,
		log:       cli.Logger.(mautrix.WarnLogger),
		pickleKey: pickleKey,

		unmanagedCryptoStore: unmanagedCryptoStore,
		managedStateStore:    managedStateStore,
		dbForManagedStores:   dbForManagedStores,
	}, nil
}

func (helper *CryptoHelper) Init() error {
	if helper == nil {
		return fmt.Errorf("crypto helper is nil")
	}
	syncer, ok := helper.client.Syncer.(mautrix.ExtensibleSyncer)
	if !ok {
		return fmt.Errorf("the client syncer must implement ExtensibleSyncer")
	}

	var stateStore crypto.StateStore
	if helper.managedStateStore != nil {
		err := helper.managedStateStore.Upgrade()
		if err != nil {
			return fmt.Errorf("failed to upgrade client state store: %w", err)
		}
		stateStore = helper.managedStateStore
	} else {
		stateStore = helper.client.StateStore.(crypto.StateStore)
	}
	var cryptoStore crypto.Store
	if helper.unmanagedCryptoStore == nil {
		managedCryptoStore := crypto.NewSQLCryptoStore(helper.dbForManagedStores, nil, helper.DBAccountID, helper.client.DeviceID, helper.pickleKey)
		if helper.client.Store == nil {
			helper.client.Store = managedCryptoStore
		} else if _, isMemory := helper.client.Store.(*mautrix.MemorySyncStore); isMemory {
			helper.client.Store = managedCryptoStore
		}
		err := managedCryptoStore.DB.Upgrade()
		if err != nil {
			return fmt.Errorf("failed to upgrade crypto state store: %w", err)
		}
		storedDeviceID := managedCryptoStore.FindDeviceID()
		if helper.LoginAs != nil {
			if storedDeviceID != "" {
				helper.LoginAs.DeviceID = storedDeviceID
			}
			helper.LoginAs.StoreCredentials = true
			helper.log.Debugfln("Logging in as %s/%s", helper.LoginAs.Identifier.User, helper.LoginAs.DeviceID)
			_, err = helper.client.Login(helper.LoginAs)
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
	helper.mach = crypto.NewOlmMachine(helper.client, crypto.NoopLogger{}, cryptoStore, stateStore)
	err := helper.mach.Load()
	if err != nil {
		return fmt.Errorf("failed to load olm account: %w", err)
	} else if err = helper.verifyDeviceKeysOnServer(); err != nil {
		return err
	}

	syncer.OnSync(helper.mach.ProcessSyncResponse)
	syncer.OnEventType(event.StateMember, helper.mach.HandleMemberEvent)
	if _, ok = helper.client.Syncer.(mautrix.DispatchableSyncer); ok {
		syncer.OnEventType(event.EventEncrypted, helper.HandleEncrypted)
	} else {
		helper.log.Warnfln("Client syncer does not implement DispatchableSyncer. Events will not be decrypted automatically.")
	}
	if helper.managedStateStore != nil {
		syncer.OnEvent(helper.client.StateStoreSyncHandler)
	}
	return nil
}

func (helper *CryptoHelper) Close() error {
	if helper.dbForManagedStores != nil {
		err := helper.dbForManagedStores.RawDB.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (helper *CryptoHelper) verifyDeviceKeysOnServer() error {
	helper.log.Debugfln("Making sure our device has the expected keys on the server")
	resp, err := helper.client.QueryKeys(&mautrix.ReqQueryKeys{
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
			helper.log.Debugfln("Olm account not shared and keys not on server, so device is probably fine")
			return nil
		}
	} else if !isShared {
		return fmt.Errorf("olm account is not marked as shared, but there are keys on the server")
	} else if ed := device.Keys.GetEd25519(helper.client.DeviceID); ownID.SigningKey != ed {
		return fmt.Errorf("mismatching identity key on server (%q != %q)", ownID.SigningKey, ed)
	}
	if !isShared {
		helper.log.Debugfln("Olm account not marked as shared, but keys on server match?")
	} else {
		helper.log.Debugfln("Olm account marked as shared and keys on server match, device is fine")
	}
	return nil
}

var NoSessionFound = crypto.NoSessionFound

const initialSessionWaitTimeout = 3 * time.Second
const extendedSessionWaitTimeout = 22 * time.Second

func (helper *CryptoHelper) HandleEncrypted(src mautrix.EventSource, evt *event.Event) {
	if helper == nil {
		return
	}
	content := evt.Content.AsEncrypted()
	helper.log.Debugfln("Decrypting %s (%s)", evt.ID, content.SessionID)

	decrypted, err := helper.Decrypt(evt)
	if errors.Is(err, NoSessionFound) {
		helper.log.Debugfln("Couldn't find session %s trying to decrypt %s, waiting %d seconds...", content.SessionID, evt.ID, int(initialSessionWaitTimeout.Seconds()))
		if helper.mach.WaitForSession(evt.RoomID, content.SenderKey, content.SessionID, initialSessionWaitTimeout) {
			helper.log.Debugfln("Got session %s after waiting, trying to decrypt %s again", content.SessionID, evt.ID)
			decrypted, err = helper.Decrypt(evt)
		} else {
			go helper.waitLongerForSession(src, evt)
			return
		}
	}
	if err != nil {
		helper.log.Warnfln("Failed to decrypt %s: %v", evt.ID, err)
		return
	}
	helper.postDecrypt(src, decrypted)
}

func (helper *CryptoHelper) postDecrypt(src mautrix.EventSource, decrypted *event.Event) {
	helper.client.Syncer.(mautrix.DispatchableSyncer).Dispatch(src|mautrix.EventSourceDecrypted, decrypted)
}

func (helper *CryptoHelper) RequestSession(roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID, userID id.UserID, deviceID id.DeviceID) {
	if helper == nil {
		return
	}
	helper.lock.RLock()
	defer helper.lock.RUnlock()
	if deviceID == "" {
		deviceID = "*"
	}
	err := helper.mach.SendRoomKeyRequest(roomID, senderKey, sessionID, "", map[id.UserID][]id.DeviceID{userID: {deviceID}})
	if err != nil {
		helper.log.Warnfln("Failed to send key request to %s/%s for %s in %s: %v", userID, deviceID, sessionID, roomID, err)
	} else {
		helper.log.Debugfln("Sent key request to %s/%s for %s in %s", userID, deviceID, sessionID, roomID)
	}
}

func (helper *CryptoHelper) waitLongerForSession(src mautrix.EventSource, evt *event.Event) {
	content := evt.Content.AsEncrypted()
	helper.log.Debugfln("Couldn't find session %s trying to decrypt %s, waiting %d more seconds...",
		content.SessionID, evt.ID, int(extendedSessionWaitTimeout.Seconds()))

	go helper.RequestSession(evt.RoomID, content.SenderKey, content.SessionID, evt.Sender, content.DeviceID)

	if !helper.mach.WaitForSession(evt.RoomID, content.SenderKey, content.SessionID, extendedSessionWaitTimeout) {
		helper.log.Debugfln("Didn't get %s, giving up on %s", content.SessionID, evt.ID)
		return
	}

	helper.log.Debugfln("Got session %s after waiting more, trying to decrypt %s again", content.SessionID, evt.ID)
	decrypted, err := helper.Decrypt(evt)
	if err != nil {
		helper.log.Warnfln("Failed to decrypt %s: %v", evt.ID, err)
		return
	}

	helper.postDecrypt(src, decrypted)
}

func (helper *CryptoHelper) WaitForSession(roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID, timeout time.Duration) bool {
	if helper == nil {
		return false
	}
	helper.lock.RLock()
	defer helper.lock.RUnlock()
	return helper.mach.WaitForSession(roomID, senderKey, sessionID, timeout)
}

func (helper *CryptoHelper) Decrypt(evt *event.Event) (*event.Event, error) {
	if helper == nil {
		return nil, fmt.Errorf("crypto helper is nil")
	}
	return helper.mach.DecryptMegolmEvent(evt)
}

func (helper *CryptoHelper) Encrypt(roomID id.RoomID, evtType event.Type, content any) (encrypted *event.EncryptedEventContent, err error) {
	if helper == nil {
		return nil, fmt.Errorf("crypto helper is nil")
	}
	helper.lock.RLock()
	defer helper.lock.RUnlock()
	encrypted, err = helper.mach.EncryptMegolmEvent(roomID, evtType, content)
	if err != nil {
		if err != crypto.SessionExpired && err != crypto.SessionNotShared && err != crypto.NoGroupSession {
			return
		}
		helper.log.Debugfln("Got %v while encrypting event for %s, sharing group session and trying again...", err, roomID)
		var users []id.UserID
		// TODO don't use managedStateStore
		users, err = helper.managedStateStore.GetRoomJoinedOrInvitedMembers(roomID)
		if err != nil {
			err = fmt.Errorf("failed to get room member list: %w", err)
		} else if err = helper.mach.ShareGroupSession(roomID, users); err != nil {
			err = fmt.Errorf("failed to share group session: %w", err)
		} else if encrypted, err = helper.mach.EncryptMegolmEvent(roomID, evtType, content); err != nil {
			err = fmt.Errorf("failed to encrypt event after re-sharing group session: %w", err)
		}
	}
	return
}
