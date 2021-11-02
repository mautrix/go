// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"strings"
	"sync"

	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/crypto/sql_store_upgrade"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

var PostgresArrayWrapper func(interface{}) interface {
	driver.Valuer
	sql.Scanner
}

// SQLCryptoStore is an implementation of a crypto Store for a database backend.
type SQLCryptoStore struct {
	DB      *sql.DB
	Log     Logger
	Dialect string

	AccountID string
	DeviceID  id.DeviceID
	SyncToken string
	PickleKey []byte
	Account   *OlmAccount

	olmSessionCache     map[id.SenderKey]map[id.SessionID]*OlmSession
	olmSessionCacheLock sync.Mutex
}

var _ Store = (*SQLCryptoStore)(nil)

// NewSQLCryptoStore initializes a new crypto Store using the given database, for a device's crypto material.
// The stored material will be encrypted with the given key.
func NewSQLCryptoStore(db *sql.DB, dialect string, accountID string, deviceID id.DeviceID, pickleKey []byte, log Logger) *SQLCryptoStore {
	return &SQLCryptoStore{
		DB:        db,
		Dialect:   dialect,
		Log:       log,
		PickleKey: pickleKey,
		AccountID: accountID,
		DeviceID:  deviceID,

		olmSessionCache: make(map[id.SenderKey]map[id.SessionID]*OlmSession),
	}
}

// CreateTables applies all the pending database migrations.
func (store *SQLCryptoStore) CreateTables() error {
	return sql_store_upgrade.Upgrade(store.DB, store.Dialect)
}

// Flush does nothing for this implementation as data is already persisted in the database.
func (store *SQLCryptoStore) Flush() error {
	return nil
}

// PutNextBatch stores the next sync batch token for the current account.
func (store *SQLCryptoStore) PutNextBatch(nextBatch string) {
	store.SyncToken = nextBatch
	_, err := store.DB.Exec(`UPDATE crypto_account SET sync_token=$1 WHERE account_id=$2`, store.SyncToken, store.AccountID)
	if err != nil {
		store.Log.Warn("Failed to store sync token: %v", err)
	}
}

// GetNextBatch retrieves the next sync batch token for the current account.
func (store *SQLCryptoStore) GetNextBatch() string {
	if store.SyncToken == "" {
		err := store.DB.
			QueryRow("SELECT sync_token FROM crypto_account WHERE account_id=$1", store.AccountID).
			Scan(&store.SyncToken)
		if err != nil && err != sql.ErrNoRows {
			store.Log.Warn("Failed to scan sync token: %v", err)
		}
	}
	return store.SyncToken
}

// PutAccount stores an OlmAccount in the database.
func (store *SQLCryptoStore) PutAccount(account *OlmAccount) error {
	store.Account = account
	bytes := account.Internal.Pickle(store.PickleKey)
	var err error
	if store.Dialect == "postgres" {
		_, err = store.DB.Exec(`
			INSERT INTO crypto_account (device_id, shared, sync_token, account, account_id) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (account_id) DO UPDATE SET shared=$2, sync_token=$3, account=$4, account_id=$5`,
			store.DeviceID, account.Shared, store.SyncToken, bytes, store.AccountID)
	} else if store.Dialect == "sqlite3" {
		_, err = store.DB.Exec("INSERT OR REPLACE INTO crypto_account (device_id, shared, sync_token, account, account_id) VALUES ($1, $2, $3, $4, $5)",
			store.DeviceID, account.Shared, store.SyncToken, bytes, store.AccountID)
	} else {
		err = fmt.Errorf("unsupported dialect %s", store.Dialect)
	}
	if err != nil {
		store.Log.Warn("Failed to store account: %v", err)
	}
	return nil
}

// GetAccount retrieves an OlmAccount from the database.
func (store *SQLCryptoStore) GetAccount() (*OlmAccount, error) {
	if store.Account == nil {
		row := store.DB.QueryRow("SELECT shared, sync_token, account FROM crypto_account WHERE account_id=$1", store.AccountID)
		acc := &OlmAccount{Internal: *olm.NewBlankAccount()}
		var accountBytes []byte
		err := row.Scan(&acc.Shared, &store.SyncToken, &accountBytes)
		if err == sql.ErrNoRows {
			return nil, nil
		} else if err != nil {
			return nil, err
		}
		err = acc.Internal.Unpickle(accountBytes, store.PickleKey)
		if err != nil {
			return nil, err
		}
		store.Account = acc
	}
	return store.Account, nil
}

// HasSession returns whether there is an Olm session for the given sender key.
func (store *SQLCryptoStore) HasSession(key id.SenderKey) bool {
	store.olmSessionCacheLock.Lock()
	cache, ok := store.olmSessionCache[key]
	store.olmSessionCacheLock.Unlock()
	if ok && len(cache) > 0 {
		return true
	}
	var sessionID id.SessionID
	err := store.DB.QueryRow("SELECT session_id FROM crypto_olm_session WHERE sender_key=$1 AND account_id=$2 LIMIT 1",
		key, store.AccountID).Scan(&sessionID)
	if err == sql.ErrNoRows {
		return false
	}
	return len(sessionID) > 0
}

// GetSessions returns all the known Olm sessions for a sender key.
func (store *SQLCryptoStore) GetSessions(key id.SenderKey) (OlmSessionList, error) {
	rows, err := store.DB.Query("SELECT session_id, session, created_at, last_used FROM crypto_olm_session WHERE sender_key=$1 AND account_id=$2 ORDER BY session_id",
		key, store.AccountID)
	if err != nil {
		return nil, err
	}
	list := OlmSessionList{}
	store.olmSessionCacheLock.Lock()
	defer store.olmSessionCacheLock.Unlock()
	cache := store.getOlmSessionCache(key)
	for rows.Next() {
		sess := OlmSession{Internal: *olm.NewBlankSession()}
		var sessionBytes []byte
		var sessionID id.SessionID
		err := rows.Scan(&sessionID, &sessionBytes, &sess.CreationTime, &sess.UseTime)
		if err != nil {
			return nil, err
		} else if existing, ok := cache[sessionID]; ok {
			list = append(list, existing)
		} else {
			err = sess.Internal.Unpickle(sessionBytes, store.PickleKey)
			if err != nil {
				return nil, err
			}
			list = append(list, &sess)
			cache[sess.ID()] = &sess
		}
	}
	return list, nil
}

func (store *SQLCryptoStore) getOlmSessionCache(key id.SenderKey) map[id.SessionID]*OlmSession {
	data, ok := store.olmSessionCache[key]
	if !ok {
		data = make(map[id.SessionID]*OlmSession)
		store.olmSessionCache[key] = data
	}
	return data
}

// GetLatestSession retrieves the Olm session for a given sender key from the database that has the largest ID.
func (store *SQLCryptoStore) GetLatestSession(key id.SenderKey) (*OlmSession, error) {
	store.olmSessionCacheLock.Lock()
	defer store.olmSessionCacheLock.Unlock()

	row := store.DB.QueryRow("SELECT session_id, session, created_at, last_used FROM crypto_olm_session WHERE sender_key=$1 AND account_id=$2 ORDER BY session_id DESC LIMIT 1",
		key, store.AccountID)

	sess := OlmSession{Internal: *olm.NewBlankSession()}
	var sessionBytes []byte
	var sessionID id.SessionID

	err := row.Scan(&sessionID, &sessionBytes, &sess.CreationTime, &sess.UseTime)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	cache := store.getOlmSessionCache(key)
	if oldSess, ok := cache[sessionID]; ok {
		return oldSess, nil
	} else if err = sess.Internal.Unpickle(sessionBytes, store.PickleKey); err != nil {
		return nil, err
	} else {
		cache[sessionID] = &sess
		return &sess, nil
	}
}

// AddSession persists an Olm session for a sender in the database.
func (store *SQLCryptoStore) AddSession(key id.SenderKey, session *OlmSession) error {
	store.olmSessionCacheLock.Lock()
	defer store.olmSessionCacheLock.Unlock()
	sessionBytes := session.Internal.Pickle(store.PickleKey)
	_, err := store.DB.Exec("INSERT INTO crypto_olm_session (session_id, sender_key, session, created_at, last_used, account_id) VALUES ($1, $2, $3, $4, $5, $6)",
		session.ID(), key, sessionBytes, session.CreationTime, session.UseTime, store.AccountID)
	store.getOlmSessionCache(key)[session.ID()] = session
	return err
}

// UpdateSession replaces the Olm session for a sender in the database.
func (store *SQLCryptoStore) UpdateSession(_ id.SenderKey, session *OlmSession) error {
	sessionBytes := session.Internal.Pickle(store.PickleKey)
	_, err := store.DB.Exec("UPDATE crypto_olm_session SET session=$1, last_used=$2 WHERE session_id=$3 AND account_id=$4",
		sessionBytes, session.UseTime, session.ID(), store.AccountID)
	return err
}

// PutGroupSession stores an inbound Megolm group session for a room, sender and session.
func (store *SQLCryptoStore) PutGroupSession(roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID, session *InboundGroupSession) error {
	sessionBytes := session.Internal.Pickle(store.PickleKey)
	forwardingChains := strings.Join(session.ForwardingChains, ",")
	var query string
	if store.Dialect == "postgres" {
		query = `INSERT INTO crypto_megolm_inbound_session
			(session_id, sender_key, signing_key, room_id, session, forwarding_chains, account_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (session_id, account_id) DO UPDATE
				SET withheld_code=NULL, withheld_reason=NULL,
					sender_key=$2, signing_key=$3, room_id=$4, session=$5, forwarding_chains=$6`
	} else {
		query = "INSERT OR REPLACE INTO crypto_megolm_inbound_session (session_id, sender_key, signing_key, room_id, session, forwarding_chains, account_id) VALUES ($1, $2, $3, $4, $5, $6, $7)"
	}
	_, err := store.DB.Exec(query,
		sessionID, senderKey, session.SigningKey, roomID, sessionBytes, forwardingChains, store.AccountID)
	return err
}

// GetGroupSession retrieves an inbound Megolm group session for a room, sender and session.
func (store *SQLCryptoStore) GetGroupSession(roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID) (*InboundGroupSession, error) {
	var signingKey, forwardingChains, withheldCode sql.NullString
	var sessionBytes []byte
	err := store.DB.QueryRow(`
		SELECT signing_key, session, forwarding_chains, withheld_code
		FROM crypto_megolm_inbound_session
		WHERE room_id=$1 AND sender_key=$2 AND session_id=$3 AND account_id=$4`,
		roomID, senderKey, sessionID, store.AccountID,
	).Scan(&signingKey, &sessionBytes, &forwardingChains, &withheldCode)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	} else if withheldCode.Valid {
		return nil, fmt.Errorf("%w (%s)", ErrGroupSessionWithheld, withheldCode.String)
	}
	igs := olm.NewBlankInboundGroupSession()
	err = igs.Unpickle(sessionBytes, store.PickleKey)
	if err != nil {
		return nil, err
	}
	return &InboundGroupSession{
		Internal:         *igs,
		SigningKey:       id.Ed25519(signingKey.String),
		SenderKey:        senderKey,
		RoomID:           roomID,
		ForwardingChains: strings.Split(forwardingChains.String, ","),
	}, nil
}

func (store *SQLCryptoStore) PutWithheldGroupSession(content event.RoomKeyWithheldEventContent) error {
	_, err := store.DB.Exec("INSERT INTO crypto_megolm_inbound_session (session_id, sender_key, room_id, withheld_code, withheld_reason, account_id) VALUES ($1, $2, $3, $4, $5, $6)",
		content.SessionID, content.SenderKey, content.RoomID, content.Code, content.Reason, store.AccountID)
	return err
}

func (store *SQLCryptoStore) GetWithheldGroupSession(roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID) (*event.RoomKeyWithheldEventContent, error) {
	var code, reason sql.NullString
	err := store.DB.QueryRow(`
		SELECT withheld_code, withheld_reason FROM crypto_megolm_inbound_session
		WHERE room_id=$1 AND sender_key=$2 AND session_id=$3 AND account_id=$4`,
		roomID, senderKey, sessionID, store.AccountID,
	).Scan(&code, &reason)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil || !code.Valid {
		return nil, err
	}
	return &event.RoomKeyWithheldEventContent{
		RoomID:    roomID,
		Algorithm: id.AlgorithmMegolmV1,
		SessionID: sessionID,
		SenderKey: senderKey,
		Code:      event.RoomKeyWithheldCode(code.String),
		Reason:    reason.String,
	}, nil
}

func (store *SQLCryptoStore) scanGroupSessionList(rows *sql.Rows) (result []*InboundGroupSession) {
	for rows.Next() {
		var roomID id.RoomID
		var signingKey, senderKey, forwardingChains sql.NullString
		var sessionBytes []byte
		err := rows.Scan(&roomID, &signingKey, &senderKey, &sessionBytes, &forwardingChains)
		if err != nil {
			store.Log.Warn("Failed to scan row: %v", err)
			continue
		}
		igs := olm.NewBlankInboundGroupSession()
		err = igs.Unpickle(sessionBytes, store.PickleKey)
		if err != nil {
			store.Log.Warn("Failed to unpickle session: %v", err)
			continue
		}
		result = append(result, &InboundGroupSession{
			Internal:         *igs,
			SigningKey:       id.Ed25519(signingKey.String),
			SenderKey:        id.Curve25519(senderKey.String),
			RoomID:           roomID,
			ForwardingChains: strings.Split(forwardingChains.String, ","),
		})
	}
	return
}

func (store *SQLCryptoStore) GetGroupSessionsForRoom(roomID id.RoomID) ([]*InboundGroupSession, error) {
	rows, err := store.DB.Query(`
		SELECT room_id, signing_key, sender_key, session, forwarding_chains
		FROM crypto_megolm_inbound_session WHERE room_id=$1 AND account_id=$2`,
		roomID, store.AccountID,
	)
	if err == sql.ErrNoRows {
		return []*InboundGroupSession{}, nil
	} else if err != nil {
		return nil, err
	}
	return store.scanGroupSessionList(rows), nil
}

func (store *SQLCryptoStore) GetAllGroupSessions() ([]*InboundGroupSession, error) {
	rows, err := store.DB.Query(`
		SELECT room_id, signing_key, sender_key, session, forwarding_chains
		FROM crypto_megolm_inbound_session WHERE account_id=$2`,
		store.AccountID,
	)
	if err == sql.ErrNoRows {
		return []*InboundGroupSession{}, nil
	} else if err != nil {
		return nil, err
	}
	return store.scanGroupSessionList(rows), nil
}

// AddOutboundGroupSession stores an outbound Megolm session, along with the information about the room and involved devices.
func (store *SQLCryptoStore) AddOutboundGroupSession(session *OutboundGroupSession) (err error) {
	sessionBytes := session.Internal.Pickle(store.PickleKey)
	if store.Dialect == "postgres" {
		_, err = store.DB.Exec(`
			INSERT INTO crypto_megolm_outbound_session (
				room_id, session_id, session, shared, max_messages, message_count, max_age, created_at, last_used, account_id
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (account_id, room_id) DO UPDATE SET session_id=$2, session=$3, shared=$4, max_messages=$5, message_count=$6, max_age=$7, created_at=$8, last_used=$9, account_id=$10`,
			session.RoomID, session.ID(), sessionBytes, session.Shared, session.MaxMessages, session.MessageCount, session.MaxAge, session.CreationTime, session.UseTime, store.AccountID)
	} else if store.Dialect == "sqlite3" {
		_, err = store.DB.Exec(`
			INSERT OR REPLACE INTO crypto_megolm_outbound_session (
				room_id, session_id, session, shared, max_messages, message_count, max_age, created_at, last_used, account_id
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			session.RoomID, session.ID(), sessionBytes, session.Shared, session.MaxMessages, session.MessageCount, session.MaxAge, session.CreationTime, session.UseTime, store.AccountID)
	} else {
		err = fmt.Errorf("unsupported dialect %s", store.Dialect)
	}
	return
}

// UpdateOutboundGroupSession replaces an outbound Megolm session with for same room and session ID.
func (store *SQLCryptoStore) UpdateOutboundGroupSession(session *OutboundGroupSession) error {
	sessionBytes := session.Internal.Pickle(store.PickleKey)
	_, err := store.DB.Exec("UPDATE crypto_megolm_outbound_session SET session=$1, message_count=$2, last_used=$3 WHERE room_id=$4 AND session_id=$5 AND account_id=$6",
		sessionBytes, session.MessageCount, session.UseTime, session.RoomID, session.ID(), store.AccountID)
	return err
}

// GetOutboundGroupSession retrieves the outbound Megolm session for the given room ID.
func (store *SQLCryptoStore) GetOutboundGroupSession(roomID id.RoomID) (*OutboundGroupSession, error) {
	var ogs OutboundGroupSession
	var sessionBytes []byte
	err := store.DB.QueryRow(`
		SELECT session, shared, max_messages, message_count, max_age, created_at, last_used
		FROM crypto_megolm_outbound_session WHERE room_id=$1 AND account_id=$2`,
		roomID, store.AccountID,
	).Scan(&sessionBytes, &ogs.Shared, &ogs.MaxMessages, &ogs.MessageCount, &ogs.MaxAge, &ogs.CreationTime, &ogs.UseTime)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	intOGS := olm.NewBlankOutboundGroupSession()
	err = intOGS.Unpickle(sessionBytes, store.PickleKey)
	if err != nil {
		return nil, err
	}
	ogs.Internal = *intOGS
	ogs.RoomID = roomID
	return &ogs, nil
}

// RemoveOutboundGroupSession removes the outbound Megolm session for the given room ID.
func (store *SQLCryptoStore) RemoveOutboundGroupSession(roomID id.RoomID) error {
	_, err := store.DB.Exec("DELETE FROM crypto_megolm_outbound_session WHERE room_id=$1 AND account_id=$2",
		roomID, store.AccountID)
	return err
}

// ValidateMessageIndex returns whether the given event information match the ones stored in the database
// for the given sender key, session ID and index.
// If the event information was not yet stored, it's stored now.
func (store *SQLCryptoStore) ValidateMessageIndex(senderKey id.SenderKey, sessionID id.SessionID, eventID id.EventID, index uint, timestamp int64) bool {
	var resultEventID id.EventID
	var resultTimestamp int64
	err := store.DB.QueryRow(
		`SELECT event_id, timestamp FROM crypto_message_index WHERE sender_key=$1 AND session_id=$2 AND "index"=$3`,
		senderKey, sessionID, index,
	).Scan(&resultEventID, &resultTimestamp)
	if err == sql.ErrNoRows {
		_, err := store.DB.Exec(`INSERT INTO crypto_message_index (sender_key, session_id, "index", event_id, timestamp) VALUES ($1, $2, $3, $4, $5)`,
			senderKey, sessionID, index, eventID, timestamp)
		if err != nil {
			store.Log.Warn("Failed to store message index: %v", err)
		}
		return true
	} else if err != nil {
		store.Log.Warn("Failed to scan message index: %v", err)
		return true
	}
	if resultEventID != eventID || resultTimestamp != timestamp {
		return false
	}
	return true
}

// GetDevices returns a map of device IDs to device identities, including the identity and signing keys, for a given user ID.
func (store *SQLCryptoStore) GetDevices(userID id.UserID) (map[id.DeviceID]*DeviceIdentity, error) {
	var ignore id.UserID
	err := store.DB.QueryRow("SELECT user_id FROM crypto_tracked_user WHERE user_id=$1", userID).Scan(&ignore)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	rows, err := store.DB.Query("SELECT device_id, identity_key, signing_key, trust, deleted, name FROM crypto_device WHERE user_id=$1", userID)
	if err != nil {
		return nil, err
	}
	data := make(map[id.DeviceID]*DeviceIdentity)
	for rows.Next() {
		var identity DeviceIdentity
		err := rows.Scan(&identity.DeviceID, &identity.IdentityKey, &identity.SigningKey, &identity.Trust, &identity.Deleted, &identity.Name)
		if err != nil {
			return nil, err
		}
		identity.UserID = userID
		data[identity.DeviceID] = &identity
	}
	return data, nil
}

// GetDevice returns the device dentity for a given user and device ID.
func (store *SQLCryptoStore) GetDevice(userID id.UserID, deviceID id.DeviceID) (*DeviceIdentity, error) {
	var identity DeviceIdentity
	err := store.DB.QueryRow(`
		SELECT identity_key, signing_key, trust, deleted, name
		FROM crypto_device WHERE user_id=$1 AND device_id=$2`,
		userID, deviceID,
	).Scan(&identity.IdentityKey, &identity.SigningKey, &identity.Trust, &identity.Deleted, &identity.Name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	identity.UserID = userID
	identity.DeviceID = deviceID
	return &identity, nil
}

// PutDevice stores a single device for a user, replacing it if it exists already.
func (store *SQLCryptoStore) PutDevice(userID id.UserID, device *DeviceIdentity) error {
	var err error
	if store.Dialect == "postgres" {
		_, err = store.DB.Exec(`
			INSERT INTO crypto_device (user_id, device_id, identity_key, signing_key, trust, deleted, name) VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (user_id, device_id) DO UPDATE SET identity_key=$3, signing_key=$4, trust=$5, deleted=$6, name=$7`,
			userID, device.DeviceID, device.IdentityKey, device.SigningKey, device.Trust, device.Deleted, device.Name)
	} else if store.Dialect == "sqlite3" {
		_, err = store.DB.Exec("INSERT OR REPLACE INTO crypto_device (user_id, device_id, identity_key, signing_key, trust, deleted, name) VALUES ($1, $2, $3, $4, $5, $6, $7)",
			userID, device.DeviceID, device.IdentityKey, device.SigningKey, device.Trust, device.Deleted, device.Name)
	} else {
		err = fmt.Errorf("unsupported dialect %s", store.Dialect)
	}
	if err != nil {
		store.Log.Warn("Failed to store device: %v", err)
	}
	return nil
}

// PutDevices stores the device identity information for the given user ID.
func (store *SQLCryptoStore) PutDevices(userID id.UserID, devices map[id.DeviceID]*DeviceIdentity) error {
	tx, err := store.DB.Begin()
	if err != nil {
		return err
	}

	if store.Dialect == "postgres" {
		_, err = tx.Exec("INSERT INTO crypto_tracked_user (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING", userID)
	} else if store.Dialect == "sqlite3" {
		_, err = tx.Exec("INSERT OR IGNORE INTO crypto_tracked_user (user_id) VALUES ($1)", userID)
	} else {
		err = fmt.Errorf("unsupported dialect %s", store.Dialect)
	}
	if err != nil {
		return fmt.Errorf("failed to add user to tracked users list: %w", err)
	}

	_, err = tx.Exec("DELETE FROM crypto_device WHERE user_id=$1", userID)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("failed to delete old devices: %w", err)
	}
	if len(devices) == 0 {
		err = tx.Commit()
		if err != nil {
			return fmt.Errorf("failed to commit changes (no devices added): %w", err)
		}
		return nil
	}
	deviceBatchLen := 5 // how many devices will be inserted per query
	deviceIDs := make([]id.DeviceID, 0, len(devices))
	for deviceID := range devices {
		deviceIDs = append(deviceIDs, deviceID)
	}
	for batchDeviceIdx := 0; batchDeviceIdx < len(deviceIDs); batchDeviceIdx += deviceBatchLen {
		var batchDevices []id.DeviceID
		if batchDeviceIdx+deviceBatchLen < len(deviceIDs) {
			batchDevices = deviceIDs[batchDeviceIdx : batchDeviceIdx+deviceBatchLen]
		} else {
			batchDevices = deviceIDs[batchDeviceIdx:]
		}
		values := make([]interface{}, 1, len(devices)*6+1)
		values[0] = userID
		valueStrings := make([]string, 0, len(devices))
		i := 2
		for _, deviceID := range batchDevices {
			identity := devices[deviceID]
			values = append(values, deviceID, identity.IdentityKey, identity.SigningKey, identity.Trust, identity.Deleted, identity.Name)
			valueStrings = append(valueStrings, fmt.Sprintf("($1, $%d, $%d, $%d, $%d, $%d, $%d)", i, i+1, i+2, i+3, i+4, i+5))
			i += 6
		}
		valueString := strings.Join(valueStrings, ",")
		_, err = tx.Exec("INSERT INTO crypto_device (user_id, device_id, identity_key, signing_key, trust, deleted, name) VALUES "+valueString, values...)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("failed to insert new devices: %w", err)
		}
	}
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit changes: %w", err)
	}
	return nil
}

// FilterTrackedUsers finds all of the user IDs out of the given ones for which the database contains identity information.
func (store *SQLCryptoStore) FilterTrackedUsers(users []id.UserID) []id.UserID {
	var rows *sql.Rows
	var err error
	if store.Dialect == "postgres" && PostgresArrayWrapper != nil {
		rows, err = store.DB.Query("SELECT user_id FROM crypto_tracked_user WHERE user_id = ANY($1)", PostgresArrayWrapper(users))
	} else {
		queryString := make([]string, len(users))
		params := make([]interface{}, len(users))
		for i, user := range users {
			queryString[i] = fmt.Sprintf("$%d", i+1)
			params[i] = user
		}
		rows, err = store.DB.Query("SELECT user_id FROM crypto_tracked_user WHERE user_id IN ("+strings.Join(queryString, ",")+")", params...)
	}
	if err != nil {
		store.Log.Warn("Failed to filter tracked users: %v", err)
		return users
	}
	var ptr int
	for rows.Next() {
		err = rows.Scan(&users[ptr])
		if err != nil {
			store.Log.Warn("Failed to scan tracked user ID: %v", err)
		} else {
			ptr++
		}
	}
	return users[:ptr]
}

// PutCrossSigningKey stores a cross-signing key of some user along with its usage.
func (store *SQLCryptoStore) PutCrossSigningKey(userID id.UserID, usage id.CrossSigningUsage, key id.Ed25519) error {
	var err error
	if store.Dialect == "postgres" {
		_, err = store.DB.Exec(`
			INSERT INTO crypto_cross_signing_keys (user_id, usage, key) VALUES ($1, $2, $3) ON CONFLICT (user_id, usage) DO UPDATE SET key=$3`,
			userID, usage, key)
	} else if store.Dialect == "sqlite3" {
		_, err = store.DB.Exec("INSERT OR REPLACE INTO crypto_cross_signing_keys (user_id, usage, key) VALUES ($1, $2, $3)",
			userID, usage, key)
	} else {
		err = fmt.Errorf("unsupported dialect %s", store.Dialect)
	}
	if err != nil {
		store.Log.Warn("Failed to store cross-signing key: %v", err)
	}
	return nil
}

// GetCrossSigningKeys retrieves a user's stored cross-signing keys.
func (store *SQLCryptoStore) GetCrossSigningKeys(userID id.UserID) (map[id.CrossSigningUsage]id.Ed25519, error) {
	rows, err := store.DB.Query("SELECT usage, key FROM crypto_cross_signing_keys WHERE user_id=$1", userID)
	if err != nil {
		return nil, err
	}
	data := make(map[id.CrossSigningUsage]id.Ed25519)
	for rows.Next() {
		var usage id.CrossSigningUsage
		var key id.Ed25519
		err := rows.Scan(&usage, &key)
		if err != nil {
			return nil, err
		}
		data[usage] = key
	}

	return data, nil
}

// PutSignature stores a signature of a cross-signing or device key along with the signer's user ID and key.
func (store *SQLCryptoStore) PutSignature(signedUserID id.UserID, signedKey id.Ed25519, signerUserID id.UserID, signerKey id.Ed25519, signature string) error {
	var err error
	if store.Dialect == "postgres" {
		_, err = store.DB.Exec(`
			INSERT INTO crypto_cross_signing_signatures (signed_user_id, signed_key, signer_user_id, signer_key, signature) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (signed_user_id, signed_key, signer_user_id, signer_key) DO UPDATE SET signature=$5`,
			signedUserID, signedKey, signerUserID, signerKey, signature)
	} else if store.Dialect == "sqlite3" {
		_, err = store.DB.Exec(`
			INSERT OR REPLACE INTO crypto_cross_signing_signatures (signed_user_id, signed_key, signer_user_id, signer_key, signature)
			VALUES ($1, $2, $3, $4, $5)`,
			signedUserID, signedKey, signerUserID, signerKey, signature)
	} else {
		err = fmt.Errorf("unsupported dialect %s", store.Dialect)
	}
	if err != nil {
		store.Log.Warn("Failed to store signature: %v", err)
	}
	return nil
}

// GetSignaturesForKeyBy retrieves the stored signatures for a given cross-signing or device key, by the given signer.
func (store *SQLCryptoStore) GetSignaturesForKeyBy(userID id.UserID, key id.Ed25519, signerID id.UserID) (map[id.Ed25519]string, error) {
	rows, err := store.DB.Query("SELECT signer_key, signature FROM crypto_cross_signing_signatures WHERE signed_user_id=$1 AND signed_key=$2 AND signer_user_id=$3", userID, key, signerID)
	if err != nil {
		return nil, err
	}
	data := make(map[id.Ed25519]string)
	for rows.Next() {
		var signerKey id.Ed25519
		var signature string
		err := rows.Scan(&signerKey, &signature)
		if err != nil {
			return nil, err
		}
		data[signerKey] = signature
	}

	return data, nil
}

// IsKeySignedBy returns whether a cross-signing or device key is signed by the given signer.
func (store *SQLCryptoStore) IsKeySignedBy(userID id.UserID, key id.Ed25519, signerID id.UserID, signerKey id.Ed25519) (bool, error) {
	sigs, err := store.GetSignaturesForKeyBy(userID, key, signerID)
	if err != nil {
		return false, err
	}
	_, ok := sigs[signerKey]
	return ok, nil
}

// DropSignaturesByKey deletes the signatures made by the given user and key from the store. It returns the number of signatures deleted.
func (store *SQLCryptoStore) DropSignaturesByKey(userID id.UserID, key id.Ed25519) (int64, error) {
	res, err := store.DB.Exec("DELETE FROM crypto_cross_signing_signatures WHERE signer_user_id=$1 AND signer_key=$2", userID, key)
	if err != nil {
		return 0, err
	}
	count, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return count, nil
}
