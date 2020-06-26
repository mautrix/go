// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/lib/pq"
	"github.com/pkg/errors"

	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/id"
)

// SQLCryptoStore is an implementation of a crypto Store for a database backend.
type SQLCryptoStore struct {
	DB      *sql.DB
	Log     Logger
	Dialect string

	DeviceID  id.DeviceID
	SyncToken string
	PickleKey []byte
	Account   *OlmAccount
}

// NewSQLCryptoStore initializes a new crypto Store using the given database, for a device's crypto material.
// The stored material will be encrypted with the given key.
func NewSQLCryptoStore(db *sql.DB, dialect string, deviceID id.DeviceID, pickleKey []byte, log Logger) *SQLCryptoStore {
	return &SQLCryptoStore{
		DB:        db,
		Dialect:   dialect,
		Log:       log,
		PickleKey: pickleKey,
		DeviceID:  deviceID,
	}
}

// CreateTables creates the necessary tables in the database for the Store.
func (store *SQLCryptoStore) CreateTables() error {
	initQueries := [...]string{
		`CREATE TABLE IF NOT EXISTS crypto_account (
			device_id  VARCHAR(255) PRIMARY KEY,
			shared     BOOLEAN      NOT NULL,
			sync_token TEXT         NOT NULL,
			account    bytea        NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS crypto_message_index (
			sender_key CHAR(43),
			session_id CHAR(43),
			"index"    INTEGER,
			event_id   VARCHAR(255) NOT NULL,
			timestamp  BIGINT       NOT NULL,
			PRIMARY KEY (sender_key, session_id, "index")
		)`,
		`CREATE TABLE IF NOT EXISTS crypto_tracked_user (
			user_id VARCHAR(255) PRIMARY KEY
		)`,
		`CREATE TABLE IF NOT EXISTS crypto_device (
			user_id      VARCHAR(255),
			device_id    VARCHAR(255),
			identity_key CHAR(43)      NOT NULL,
			signing_key  CHAR(43)      NOT NULL,
			trust        SMALLINT      NOT NULL,
			deleted      BOOLEAN       NOT NULL,
			name         VARCHAR(255)  NOT NULL,
			PRIMARY KEY (user_id, device_id)
		)`,
		`CREATE TABLE IF NOT EXISTS crypto_olm_session (
			session_id   CHAR(43)  PRIMARY KEY,
			sender_key   CHAR(43)  NOT NULL,
			session      bytea     NOT NULL,
			created_at   timestamp NOT NULL,
			last_used    timestamp NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS crypto_megolm_inbound_session (
			session_id   CHAR(43)     PRIMARY KEY,
			sender_key   CHAR(43)     NOT NULL,
			signing_key  CHAR(43)     NOT NULL,
			room_id      VARCHAR(255) NOT NULL,
			session      bytea        NOT NULL,
			forwarding_chains bytea   NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS crypto_megolm_outbound_session (
			room_id       VARCHAR(255) PRIMARY KEY,
			session_id    CHAR(43)     NOT NULL UNIQUE,
			session       bytea        NOT NULL,
			shared        BOOLEAN      NOT NULL,
			max_messages  INTEGER      NOT NULL,
			message_count INTEGER      NOT NULL,
			max_age       BIGINT       NOT NULL,
			created_at    timestamp    NOT NULL,
			last_used     timestamp    NOT NULL
		)`,
	}

	tx, err := store.DB.Begin()
	if err != nil {
		return err
	}

	for _, query := range initQueries {
		_, err = tx.Exec(query)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
	}

	return tx.Commit()
}

// Flush does nothing for this implementation as data is already persisted in the database.
func (store *SQLCryptoStore) Flush() error {
	return nil
}

// PutNextBatch stores the next sync batch token for the current account.
func (store *SQLCryptoStore) PutNextBatch(nextBatch string) {
	store.SyncToken = nextBatch
	_, err := store.DB.Exec(`UPDATE crypto_account SET sync_token=$1 WHERE device_id=$2`, store.SyncToken, store.DeviceID)
	if err != nil {
		store.Log.Warn("Failed to store sync token: %v", err)
	}
}

// GetNextBatch retrieves the next sync batch token for the current account.
func (store *SQLCryptoStore) GetNextBatch() string {
	if store.SyncToken == "" {
		err := store.DB.
			QueryRow("SELECT sync_token FROM crypto_account WHERE device_id=$1", store.DeviceID).
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
			INSERT INTO crypto_account (device_id, shared, sync_token, account) VALUES ($1, $2, $3, $4)
			ON CONFLICT (device_id) DO UPDATE SET shared=$2, sync_token=$3, account=$4`,
			store.DeviceID, account.Shared, store.SyncToken, bytes)
	} else if store.Dialect == "sqlite3" {
		_, err = store.DB.Exec("INSERT OR REPLACE INTO crypto_account (device_id, shared, sync_token, account) VALUES ($1, $2, $3, $4)",
			store.DeviceID, account.Shared, store.SyncToken, bytes)
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
		row := store.DB.QueryRow("SELECT shared, sync_token, account FROM crypto_account WHERE device_id=$1", store.DeviceID)
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
	// TODO this may need to be changed if olm sessions start expiring
	var sessionID id.SessionID
	err := store.DB.QueryRow("SELECT session_id FROM crypto_olm_session WHERE sender_key=$1 LIMIT 1", key).Scan(&sessionID)
	if err == sql.ErrNoRows {
		return false
	}
	return len(sessionID) > 0
}

// GetSessions returns all the known Olm sessions for a sender key.
func (store *SQLCryptoStore) GetSessions(key id.SenderKey) (OlmSessionList, error) {
	rows, err := store.DB.Query("SELECT session, created_at, last_used FROM crypto_olm_session WHERE sender_key=$1 ORDER BY session_id", key)
	if err != nil {
		return nil, err
	}
	list := OlmSessionList{}
	for rows.Next() {
		sess := OlmSession{Internal: *olm.NewBlankSession()}
		var sessionBytes []byte
		err := rows.Scan(&sessionBytes, &sess.CreationTime, &sess.UseTime)
		if err != nil {
			return nil, err
		}
		err = sess.Internal.Unpickle(sessionBytes, store.PickleKey)
		if err != nil {
			return nil, err
		}
		list = append(list, &sess)
	}
	return list, nil
}

// GetLatestSession retrieves the Olm session for a given sender key from the database that has the largest ID.
func (store *SQLCryptoStore) GetLatestSession(key id.SenderKey) (*OlmSession, error) {
	row := store.DB.QueryRow("SELECT session, created_at, last_used FROM crypto_olm_session WHERE sender_key=$1 ORDER BY session_id DESC LIMIT 1", key)
	sess := OlmSession{Internal: *olm.NewBlankSession()}
	var sessionBytes []byte
	err := row.Scan(&sessionBytes, &sess.CreationTime, &sess.UseTime)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &sess, sess.Internal.Unpickle(sessionBytes, store.PickleKey)
}

// AddSession persists an Olm session for a sender in the database.
func (store *SQLCryptoStore) AddSession(key id.SenderKey, session *OlmSession) error {
	sessionBytes := session.Internal.Pickle(store.PickleKey)
	_, err := store.DB.Exec("INSERT INTO crypto_olm_session (session_id, sender_key, session, created_at, last_used) VALUES ($1, $2, $3, $4, $5)",
		session.ID(), key, sessionBytes, session.CreationTime, session.UseTime)
	return err
}

// UpdateSession replaces the Olm session for a sender in the database.
func (store *SQLCryptoStore) UpdateSession(key id.SenderKey, session *OlmSession) error {
	sessionBytes := session.Internal.Pickle(store.PickleKey)
	_, err := store.DB.Exec("UPDATE crypto_olm_session SET session=$1, last_used=$2 WHERE session_id=$3",
		sessionBytes, session.UseTime, session.ID())
	return err
}

// PutGroupSession stores an inbound Megolm group session for a room, sender and session.
func (store *SQLCryptoStore) PutGroupSession(roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID, session *InboundGroupSession) error {
	sessionBytes := session.Internal.Pickle(store.PickleKey)
	forwardingChains := strings.Join(session.ForwardingChains, ",")
	_, err := store.DB.Exec("INSERT INTO crypto_megolm_inbound_session (session_id, sender_key, signing_key, room_id, session, forwarding_chains) VALUES ($1, $2, $3, $4, $5, $6)",
		sessionID, senderKey, session.SigningKey, roomID, sessionBytes, forwardingChains)
	return err
}

// GetGroupSession retrieves an inbound Megolm group session for a room, sender and session.
func (store *SQLCryptoStore) GetGroupSession(roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID) (*InboundGroupSession, error) {
	var signingKey id.Ed25519
	var sessionBytes []byte
	var forwardingChains string
	err := store.DB.QueryRow(`
		SELECT signing_key, session, forwarding_chains
		FROM crypto_megolm_inbound_session
		WHERE room_id=$1 AND sender_key=$2 AND session_id=$3`,
		roomID, senderKey, sessionID,
	).Scan(&signingKey, &sessionBytes, &forwardingChains)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	igs := olm.NewBlankInboundGroupSession()
	err = igs.Unpickle(sessionBytes, store.PickleKey)
	if err != nil {
		return nil, err
	}
	return &InboundGroupSession{
		Internal:         *igs,
		SigningKey:       signingKey,
		SenderKey:        senderKey,
		RoomID:           roomID,
		ForwardingChains: strings.Split(forwardingChains, ","),
	}, nil
}

// AddOutboundGroupSession stores an outbound Megolm session, along with the information about the room and involved devices.
func (store *SQLCryptoStore) AddOutboundGroupSession(session *OutboundGroupSession) (err error) {
	sessionBytes := session.Internal.Pickle(store.PickleKey)
	if store.Dialect == "postgres" {
		_, err = store.DB.Exec(`
			INSERT INTO crypto_megolm_outbound_session (
				room_id, session_id, session, shared, max_messages, message_count, max_age, created_at, last_used
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (room_id) DO UPDATE SET session_id=$2, session=$3, shared=$4, max_messages=$5, message_count=$6, max_age=$7, created_at=$8, last_used=$9`,
			session.RoomID, session.ID(), sessionBytes, session.Shared, session.MaxMessages, session.MessageCount, session.MaxAge, session.CreationTime, session.UseTime)
	} else if store.Dialect == "sqlite3" {
		_, err = store.DB.Exec(`
			INSERT OR REPLACE INTO crypto_megolm_outbound_session (
				room_id, session_id, session, shared, max_messages, message_count, max_age, created_at, last_used
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			session.RoomID, session.ID(), sessionBytes, session.Shared, session.MaxMessages, session.MessageCount, session.MaxAge, session.CreationTime, session.UseTime)
	} else {
		err = fmt.Errorf("unsupported dialect %s", store.Dialect)
	}
	return
}

// UpdateOutboundGroupSession replaces an outbound Megolm session with for same room and session ID.
func (store *SQLCryptoStore) UpdateOutboundGroupSession(session *OutboundGroupSession) error {
	sessionBytes := session.Internal.Pickle(store.PickleKey)
	_, err := store.DB.Exec("UPDATE crypto_megolm_outbound_session SET session=$1, message_count=$2, last_used=$3 WHERE room_id=$4 AND session_id=$5",
		sessionBytes, session.MessageCount, session.UseTime, session.RoomID, session.ID())
	return err
}

// GetOutboundGroupSession retrieves the outbound Megolm session for the given room ID.
func (store *SQLCryptoStore) GetOutboundGroupSession(roomID id.RoomID) (*OutboundGroupSession, error) {
	var ogs OutboundGroupSession
	var sessionBytes []byte
	err := store.DB.QueryRow(`
		SELECT session, shared, max_messages, message_count, max_age, created_at, last_used
		FROM crypto_megolm_outbound_session WHERE room_id=$1`,
		roomID,
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
	_, err := store.DB.Exec("DELETE FROM crypto_megolm_outbound_session WHERE room_id=$1", roomID)
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
	return &identity, nil
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
		return errors.Wrap(err, "failed to add user to tracked users list")
	}

	_, err = tx.Exec("DELETE FROM crypto_device WHERE user_id=$1", userID)
	if err != nil {
		_ = tx.Rollback()
		return errors.Wrap(err, "failed to delete old devices")
	}
	if len(devices) == 0 {
		err = tx.Commit()
		if err != nil {
			return errors.Wrap(err, "failed to commit changes (no devices added)")
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
			return errors.Wrap(err, "failed to insert new devices")
		}
	}
	err = tx.Commit()
	if err != nil {
		return errors.Wrap(err, "failed to commit changes")
	}
	return nil
}

// FilterTrackedUsers finds all of the user IDs out of the given ones for which the database contains identity information.
func (store *SQLCryptoStore) FilterTrackedUsers(users []id.UserID) []id.UserID {
	var rows *sql.Rows
	var err error
	if store.Dialect == "postgres" {
		rows, err = store.DB.Query("SELECT user_id FROM crypto_tracked_user WHERE user_id = ANY($1)", pq.Array(users))
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
