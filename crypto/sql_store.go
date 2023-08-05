// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix"
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
	DB *dbutil.Database

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
func NewSQLCryptoStore(db *dbutil.Database, log dbutil.DatabaseLogger, accountID string, deviceID id.DeviceID, pickleKey []byte) *SQLCryptoStore {
	return &SQLCryptoStore{
		DB:        db.Child(sql_store_upgrade.VersionTableName, sql_store_upgrade.Table, log),
		PickleKey: pickleKey,
		AccountID: accountID,
		DeviceID:  deviceID,

		olmSessionCache: make(map[id.SenderKey]map[id.SessionID]*OlmSession),
	}
}

// Flush does nothing for this implementation as data is already persisted in the database.
func (store *SQLCryptoStore) Flush() error {
	return nil
}

// PutNextBatch stores the next sync batch token for the current account.
func (store *SQLCryptoStore) PutNextBatch(nextBatch string) error {
	store.SyncToken = nextBatch
	_, err := store.DB.Exec(`UPDATE crypto_account SET sync_token=$1 WHERE account_id=$2`, store.SyncToken, store.AccountID)
	return err
}

// GetNextBatch retrieves the next sync batch token for the current account.
func (store *SQLCryptoStore) GetNextBatch() (string, error) {
	if store.SyncToken == "" {
		err := store.DB.
			QueryRow("SELECT sync_token FROM crypto_account WHERE account_id=$1", store.AccountID).
			Scan(&store.SyncToken)
		if !errors.Is(err, sql.ErrNoRows) {
			return "", err
		}
	}
	return store.SyncToken, nil
}

var _ mautrix.SyncStore = (*SQLCryptoStore)(nil)

func (store *SQLCryptoStore) SaveFilterID(_ id.UserID, _ string) {}
func (store *SQLCryptoStore) LoadFilterID(_ id.UserID) string    { return "" }

func (store *SQLCryptoStore) SaveNextBatch(_ id.UserID, nextBatchToken string) {
	err := store.PutNextBatch(nextBatchToken)
	if err != nil {
		// TODO handle error
	}
}

func (store *SQLCryptoStore) LoadNextBatch(_ id.UserID) string {
	nb, err := store.GetNextBatch()
	if err != nil {
		// TODO handle error
	}
	return nb
}

func (store *SQLCryptoStore) FindDeviceID() (deviceID id.DeviceID) {
	err := store.DB.QueryRow("SELECT device_id FROM crypto_account WHERE account_id=$1", store.AccountID).Scan(&deviceID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		// TODO return error
		store.DB.Log.Warn("Failed to scan device ID: %v", err)
	}
	return
}

// PutAccount stores an OlmAccount in the database.
func (store *SQLCryptoStore) PutAccount(account *OlmAccount) error {
	store.Account = account
	bytes := account.Internal.Pickle(store.PickleKey)
	_, err := store.DB.Exec(`
		INSERT INTO crypto_account (device_id, shared, sync_token, account, account_id) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (account_id) DO UPDATE SET shared=excluded.shared, sync_token=excluded.sync_token,
											   account=excluded.account, account_id=excluded.account_id
	`, store.DeviceID, account.Shared, store.SyncToken, bytes, store.AccountID)
	return err
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
	rows, err := store.DB.Query("SELECT session_id, session, created_at, last_encrypted, last_decrypted FROM crypto_olm_session WHERE sender_key=$1 AND account_id=$2 ORDER BY last_decrypted DESC",
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
		err = rows.Scan(&sessionID, &sessionBytes, &sess.CreationTime, &sess.LastEncryptedTime, &sess.LastDecryptedTime)
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

	row := store.DB.QueryRow("SELECT session_id, session, created_at, last_encrypted, last_decrypted FROM crypto_olm_session WHERE sender_key=$1 AND account_id=$2 ORDER BY last_decrypted DESC LIMIT 1",
		key, store.AccountID)

	sess := OlmSession{Internal: *olm.NewBlankSession()}
	var sessionBytes []byte
	var sessionID id.SessionID

	err := row.Scan(&sessionID, &sessionBytes, &sess.CreationTime, &sess.LastEncryptedTime, &sess.LastDecryptedTime)
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
	_, err := store.DB.Exec("INSERT INTO crypto_olm_session (session_id, sender_key, session, created_at, last_encrypted, last_decrypted, account_id) VALUES ($1, $2, $3, $4, $5, $6, $7)",
		session.ID(), key, sessionBytes, session.CreationTime, session.LastEncryptedTime, session.LastDecryptedTime, store.AccountID)
	store.getOlmSessionCache(key)[session.ID()] = session
	return err
}

// UpdateSession replaces the Olm session for a sender in the database.
func (store *SQLCryptoStore) UpdateSession(_ id.SenderKey, session *OlmSession) error {
	sessionBytes := session.Internal.Pickle(store.PickleKey)
	_, err := store.DB.Exec("UPDATE crypto_olm_session SET session=$1, last_encrypted=$2, last_decrypted=$3 WHERE session_id=$4 AND account_id=$5",
		sessionBytes, session.LastEncryptedTime, session.LastDecryptedTime, session.ID(), store.AccountID)
	return err
}

func intishPtr[T int | int64](i T) *T {
	if i == 0 {
		return nil
	}
	return &i
}

func datePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// PutGroupSession stores an inbound Megolm group session for a room, sender and session.
func (store *SQLCryptoStore) PutGroupSession(roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID, session *InboundGroupSession) error {
	sessionBytes := session.Internal.Pickle(store.PickleKey)
	forwardingChains := strings.Join(session.ForwardingChains, ",")
	ratchetSafety, err := json.Marshal(&session.RatchetSafety)
	if err != nil {
		return fmt.Errorf("failed to marshal ratchet safety info: %w", err)
	}
	_, err = store.DB.Exec(`
		INSERT INTO crypto_megolm_inbound_session (
			session_id, sender_key, signing_key, room_id, session, forwarding_chains,
			ratchet_safety, received_at, max_age, max_messages, is_scheduled, account_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (session_id, account_id) DO UPDATE
		    SET withheld_code=NULL, withheld_reason=NULL, sender_key=excluded.sender_key, signing_key=excluded.signing_key,
		        room_id=excluded.room_id, session=excluded.session, forwarding_chains=excluded.forwarding_chains,
		        ratchet_safety=excluded.ratchet_safety, received_at=excluded.received_at,
		        max_age=excluded.max_age, max_messages=excluded.max_messages, is_scheduled=excluded.is_scheduled
	`,
		sessionID, senderKey, session.SigningKey, roomID, sessionBytes, forwardingChains,
		ratchetSafety, datePtr(session.ReceivedAt), intishPtr(session.MaxAge), intishPtr(session.MaxMessages),
		session.IsScheduled, store.AccountID,
	)
	return err
}

// GetGroupSession retrieves an inbound Megolm group session for a room, sender and session.
func (store *SQLCryptoStore) GetGroupSession(roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID) (*InboundGroupSession, error) {
	var senderKeyDB, signingKey, forwardingChains, withheldCode, withheldReason sql.NullString
	var sessionBytes, ratchetSafetyBytes []byte
	var receivedAt sql.NullTime
	var maxAge, maxMessages sql.NullInt64
	var isScheduled bool
	err := store.DB.QueryRow(`
		SELECT sender_key, signing_key, session, forwarding_chains, withheld_code, withheld_reason, ratchet_safety, received_at, max_age, max_messages, is_scheduled
		FROM crypto_megolm_inbound_session
		WHERE room_id=$1 AND (sender_key=$2 OR $2 = '') AND session_id=$3 AND account_id=$4`,
		roomID, senderKey, sessionID, store.AccountID,
	).Scan(&senderKeyDB, &signingKey, &sessionBytes, &forwardingChains, &withheldCode, &withheldReason, &ratchetSafetyBytes, &receivedAt, &maxAge, &maxMessages, &isScheduled)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	} else if withheldCode.Valid {
		return nil, &event.RoomKeyWithheldEventContent{
			RoomID:    roomID,
			Algorithm: id.AlgorithmMegolmV1,
			SessionID: sessionID,
			SenderKey: senderKey,
			Code:      event.RoomKeyWithheldCode(withheldCode.String),
			Reason:    withheldReason.String,
		}
	}
	igs := olm.NewBlankInboundGroupSession()
	err = igs.Unpickle(sessionBytes, store.PickleKey)
	if err != nil {
		return nil, err
	}
	var chains []string
	if forwardingChains.String != "" {
		chains = strings.Split(forwardingChains.String, ",")
	}
	var rs RatchetSafety
	if len(ratchetSafetyBytes) > 0 {
		err = json.Unmarshal(ratchetSafetyBytes, &rs)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal ratchet safety info: %w", err)
		}
	}
	if senderKey == "" {
		senderKey = id.Curve25519(senderKeyDB.String)
	}
	return &InboundGroupSession{
		Internal:         *igs,
		SigningKey:       id.Ed25519(signingKey.String),
		SenderKey:        senderKey,
		RoomID:           roomID,
		ForwardingChains: chains,
		RatchetSafety:    rs,
		ReceivedAt:       receivedAt.Time,
		MaxAge:           maxAge.Int64,
		MaxMessages:      int(maxMessages.Int64),
		IsScheduled:      isScheduled,
	}, nil
}

func (store *SQLCryptoStore) RedactGroupSession(_ id.RoomID, _ id.SenderKey, sessionID id.SessionID, reason string) error {
	_, err := store.DB.Exec(`
		UPDATE crypto_megolm_inbound_session
		SET withheld_code=$1, withheld_reason=$2, session=NULL, forwarding_chains=NULL
		WHERE session_id=$3 AND account_id=$4 AND session IS NOT NULL
	`, event.RoomKeyWithheldBeeperRedacted, "Session redacted: "+reason, sessionID, store.AccountID)
	return err
}

func (store *SQLCryptoStore) RedactGroupSessions(roomID id.RoomID, senderKey id.SenderKey, reason string) ([]id.SessionID, error) {
	if roomID == "" && senderKey == "" {
		return nil, fmt.Errorf("room ID or sender key must be provided for redacting sessions")
	}
	res, err := store.DB.Query(`
		UPDATE crypto_megolm_inbound_session
		SET withheld_code=$1, withheld_reason=$2, session=NULL, forwarding_chains=NULL
		WHERE (room_id=$3 OR $3='') AND (sender_key=$4 OR $4='') AND account_id=$5
		  AND session IS NOT NULL AND is_scheduled=false AND received_at IS NOT NULL
		RETURNING session_id
	`, event.RoomKeyWithheldBeeperRedacted, "Session redacted: "+reason, roomID, senderKey, store.AccountID)
	var sessionIDs []id.SessionID
	for res.Next() {
		var sessionID id.SessionID
		_ = res.Scan(&sessionID)
		sessionIDs = append(sessionIDs, sessionID)
	}
	return sessionIDs, err
}

func (store *SQLCryptoStore) RedactExpiredGroupSessions() ([]id.SessionID, error) {
	var query string
	switch store.DB.Dialect {
	case dbutil.Postgres:
		query = `
			UPDATE crypto_megolm_inbound_session
			SET withheld_code=$1, withheld_reason=$2, session=NULL, forwarding_chains=NULL
			WHERE account_id=$3 AND session IS NOT NULL AND is_scheduled=false
			  AND received_at IS NOT NULL and max_age IS NOT NULL
			  AND received_at + 2 * (max_age * interval '1 millisecond') < now()
			RETURNING session_id
		`
	case dbutil.SQLite:
		query = `
			UPDATE crypto_megolm_inbound_session
			SET withheld_code=$1, withheld_reason=$2, session=NULL, forwarding_chains=NULL
			WHERE account_id=$3 AND session IS NOT NULL AND is_scheduled=false
			  AND received_at IS NOT NULL and max_age IS NOT NULL
			  AND unixepoch(received_at) + (2 * max_age / 1000) < unixepoch(date('now'))
			RETURNING session_id
		`
	default:
		return nil, fmt.Errorf("unsupported dialect")
	}
	res, err := store.DB.Query(query, event.RoomKeyWithheldBeeperRedacted, "Session redacted: expired", store.AccountID)
	var sessionIDs []id.SessionID
	for res.Next() {
		var sessionID id.SessionID
		_ = res.Scan(&sessionID)
		sessionIDs = append(sessionIDs, sessionID)
	}
	return sessionIDs, err
}

func (store *SQLCryptoStore) RedactOutdatedGroupSessions() ([]id.SessionID, error) {
	res, err := store.DB.Query(`
			UPDATE crypto_megolm_inbound_session
			SET withheld_code=$1, withheld_reason=$2, session=NULL, forwarding_chains=NULL
			WHERE account_id=$3 AND session IS NOT NULL AND received_at IS NULL
			RETURNING session_id
		`, event.RoomKeyWithheldBeeperRedacted, "Session redacted: outdated", store.AccountID)
	var sessionIDs []id.SessionID
	for res.Next() {
		var sessionID id.SessionID
		_ = res.Scan(&sessionID)
		sessionIDs = append(sessionIDs, sessionID)
	}
	return sessionIDs, err
}

func (store *SQLCryptoStore) PutWithheldGroupSession(content event.RoomKeyWithheldEventContent) error {
	_, err := store.DB.Exec("INSERT INTO crypto_megolm_inbound_session (session_id, sender_key, room_id, withheld_code, withheld_reason, received_at, account_id) VALUES ($1, $2, $3, $4, $5, $6, $7)",
		content.SessionID, content.SenderKey, content.RoomID, content.Code, content.Reason, time.Now().UTC(), store.AccountID)
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

func (store *SQLCryptoStore) scanGroupSessionList(rows dbutil.Rows) (result []*InboundGroupSession, err error) {
	for rows.Next() {
		var roomID id.RoomID
		var signingKey, senderKey, forwardingChains sql.NullString
		var sessionBytes, ratchetSafetyBytes []byte
		var receivedAt sql.NullTime
		var maxAge, maxMessages sql.NullInt64
		var isScheduled bool
		err = rows.Scan(&roomID, &signingKey, &senderKey, &sessionBytes, &forwardingChains, &ratchetSafetyBytes, &receivedAt, &maxAge, &maxMessages, &isScheduled)
		if err != nil {
			return
		}
		igs := olm.NewBlankInboundGroupSession()
		err = igs.Unpickle(sessionBytes, store.PickleKey)
		if err != nil {
			return
		}
		var chains []string
		if forwardingChains.String != "" {
			chains = strings.Split(forwardingChains.String, ",")
		}
		var rs RatchetSafety
		if len(ratchetSafetyBytes) > 0 {
			err = json.Unmarshal(ratchetSafetyBytes, &rs)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal ratchet safety info: %w", err)
			}
		}
		result = append(result, &InboundGroupSession{
			Internal:         *igs,
			SigningKey:       id.Ed25519(signingKey.String),
			SenderKey:        id.Curve25519(senderKey.String),
			RoomID:           roomID,
			ForwardingChains: chains,
			RatchetSafety:    rs,
			ReceivedAt:       receivedAt.Time,
			MaxAge:           maxAge.Int64,
			MaxMessages:      int(maxMessages.Int64),
			IsScheduled:      isScheduled,
		})
	}
	return
}

func (store *SQLCryptoStore) GetGroupSessionsForRoom(roomID id.RoomID) ([]*InboundGroupSession, error) {
	rows, err := store.DB.Query(`
		SELECT room_id, signing_key, sender_key, session, forwarding_chains, ratchet_safety, received_at, max_age, max_messages, is_scheduled
		FROM crypto_megolm_inbound_session WHERE room_id=$1 AND account_id=$2 AND session IS NOT NULL`,
		roomID, store.AccountID,
	)
	if err == sql.ErrNoRows {
		return []*InboundGroupSession{}, nil
	} else if err != nil {
		return nil, err
	}
	return store.scanGroupSessionList(rows)
}

func (store *SQLCryptoStore) GetAllGroupSessions() ([]*InboundGroupSession, error) {
	rows, err := store.DB.Query(`
		SELECT room_id, signing_key, sender_key, session, forwarding_chains, ratchet_safety, received_at, max_age, max_messages, is_scheduled
		FROM crypto_megolm_inbound_session WHERE account_id=$2 AND session IS NOT NULL`,
		store.AccountID,
	)
	if err == sql.ErrNoRows {
		return []*InboundGroupSession{}, nil
	} else if err != nil {
		return nil, err
	}
	return store.scanGroupSessionList(rows)
}

// AddOutboundGroupSession stores an outbound Megolm session, along with the information about the room and involved devices.
func (store *SQLCryptoStore) AddOutboundGroupSession(session *OutboundGroupSession) error {
	sessionBytes := session.Internal.Pickle(store.PickleKey)
	_, err := store.DB.Exec(`
		INSERT INTO crypto_megolm_outbound_session
			(room_id, session_id, session, shared, max_messages, message_count, max_age, created_at, last_used, account_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (account_id, room_id) DO UPDATE
			SET session_id=excluded.session_id, session=excluded.session, shared=excluded.shared,
				max_messages=excluded.max_messages, message_count=excluded.message_count, max_age=excluded.max_age,
				created_at=excluded.created_at, last_used=excluded.last_used, account_id=excluded.account_id
	`, session.RoomID, session.ID(), sessionBytes, session.Shared, session.MaxMessages, session.MessageCount,
		session.MaxAge.Milliseconds(), session.CreationTime, session.LastEncryptedTime, store.AccountID)
	return err
}

// UpdateOutboundGroupSession replaces an outbound Megolm session with for same room and session ID.
func (store *SQLCryptoStore) UpdateOutboundGroupSession(session *OutboundGroupSession) error {
	sessionBytes := session.Internal.Pickle(store.PickleKey)
	_, err := store.DB.Exec("UPDATE crypto_megolm_outbound_session SET session=$1, message_count=$2, last_used=$3 WHERE room_id=$4 AND session_id=$5 AND account_id=$6",
		sessionBytes, session.MessageCount, session.LastEncryptedTime, session.RoomID, session.ID(), store.AccountID)
	return err
}

// GetOutboundGroupSession retrieves the outbound Megolm session for the given room ID.
func (store *SQLCryptoStore) GetOutboundGroupSession(roomID id.RoomID) (*OutboundGroupSession, error) {
	var ogs OutboundGroupSession
	var sessionBytes []byte
	var maxAgeMS int64
	err := store.DB.QueryRow(`
		SELECT session, shared, max_messages, message_count, max_age, created_at, last_used
		FROM crypto_megolm_outbound_session WHERE room_id=$1 AND account_id=$2`,
		roomID, store.AccountID,
	).Scan(&sessionBytes, &ogs.Shared, &ogs.MaxMessages, &ogs.MessageCount, &maxAgeMS, &ogs.CreationTime, &ogs.LastEncryptedTime)
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
	ogs.MaxAge = time.Duration(maxAgeMS) * time.Millisecond
	return &ogs, nil
}

// RemoveOutboundGroupSession removes the outbound Megolm session for the given room ID.
func (store *SQLCryptoStore) RemoveOutboundGroupSession(roomID id.RoomID) error {
	_, err := store.DB.Exec("DELETE FROM crypto_megolm_outbound_session WHERE room_id=$1 AND account_id=$2",
		roomID, store.AccountID)
	return err
}

// ValidateMessageIndex returns whether the given event information match the ones stored in the database
// for the given sender key, session ID and index. If the index hasn't been stored, this will store it.
func (store *SQLCryptoStore) ValidateMessageIndex(ctx context.Context, senderKey id.SenderKey, sessionID id.SessionID, eventID id.EventID, index uint, timestamp int64) (bool, error) {
	const validateQuery = `
	INSERT INTO crypto_message_index (sender_key, session_id, "index", event_id, timestamp)
	VALUES ($1, $2, $3, $4, $5)
	-- have to update something so that RETURNING * always returns the row
	ON CONFLICT (sender_key, session_id, "index") DO UPDATE SET sender_key=excluded.sender_key
	RETURNING event_id, timestamp
	`
	var expectedEventID id.EventID
	var expectedTimestamp int64
	err := store.DB.QueryRowContext(ctx, validateQuery, senderKey, sessionID, index, eventID, timestamp).Scan(&expectedEventID, &expectedTimestamp)
	if err != nil {
		return false, err
	} else if expectedEventID != eventID || expectedTimestamp != timestamp {
		zerolog.Ctx(ctx).Debug().
			Uint("message_index", index).
			Str("expected_event_id", expectedEventID.String()).
			Int64("expected_timestamp", expectedTimestamp).
			Int64("actual_timestamp", timestamp).
			Msg("Failed to validate that message index wasn't duplicated")
		return false, nil
	}
	return true, nil
}

// GetDevices returns a map of device IDs to device identities, including the identity and signing keys, for a given user ID.
func (store *SQLCryptoStore) GetDevices(userID id.UserID) (map[id.DeviceID]*id.Device, error) {
	var ignore id.UserID
	err := store.DB.QueryRow("SELECT user_id FROM crypto_tracked_user WHERE user_id=$1", userID).Scan(&ignore)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	rows, err := store.DB.Query("SELECT device_id, identity_key, signing_key, trust, deleted, name FROM crypto_device WHERE user_id=$1 AND deleted=false", userID)
	if err != nil {
		return nil, err
	}
	data := make(map[id.DeviceID]*id.Device)
	for rows.Next() {
		var identity id.Device
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
func (store *SQLCryptoStore) GetDevice(userID id.UserID, deviceID id.DeviceID) (*id.Device, error) {
	var identity id.Device
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

// FindDeviceByKey finds a specific device by its sender key.
func (store *SQLCryptoStore) FindDeviceByKey(userID id.UserID, identityKey id.IdentityKey) (*id.Device, error) {
	var identity id.Device
	err := store.DB.QueryRow(`
		SELECT device_id, signing_key, trust, deleted, name
		FROM crypto_device WHERE user_id=$1 AND identity_key=$2`,
		userID, identityKey,
	).Scan(&identity.DeviceID, &identity.SigningKey, &identity.Trust, &identity.Deleted, &identity.Name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	identity.UserID = userID
	identity.IdentityKey = identityKey
	return &identity, nil
}

const deviceInsertQuery = `
INSERT INTO crypto_device (user_id, device_id, identity_key, signing_key, trust, deleted, name)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (user_id, device_id) DO UPDATE
    SET identity_key=excluded.identity_key, deleted=excluded.deleted, trust=excluded.trust, name=excluded.name
`

var deviceMassInsertTemplate = strings.ReplaceAll(deviceInsertQuery, "($1, $2, $3, $4, $5, $6, $7)", "%s")

// PutDevice stores a single device for a user, replacing it if it exists already.
func (store *SQLCryptoStore) PutDevice(userID id.UserID, device *id.Device) error {
	_, err := store.DB.Exec(deviceInsertQuery,
		userID, device.DeviceID, device.IdentityKey, device.SigningKey, device.Trust, device.Deleted, device.Name)
	return err
}

// PutDevices stores the device identity information for the given user ID.
func (store *SQLCryptoStore) PutDevices(userID id.UserID, devices map[id.DeviceID]*id.Device) error {
	tx, err := store.DB.Begin()
	if err != nil {
		return err
	}

	_, err = tx.Exec("INSERT INTO crypto_tracked_user (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING", userID)
	if err != nil {
		return fmt.Errorf("failed to add user to tracked users list: %w", err)
	}

	_, err = tx.Exec("UPDATE crypto_device SET deleted=true WHERE user_id=$1", userID)
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
	const valueStringFormat = "($1, $%d, $%d, $%d, $%d, $%d, $%d)"
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
			valueStrings = append(valueStrings, fmt.Sprintf(valueStringFormat, i, i+1, i+2, i+3, i+4, i+5))
			i += 6
		}
		valueString := strings.Join(valueStrings, ",")
		_, err = tx.Exec(fmt.Sprintf(deviceMassInsertTemplate, valueString), values...)
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

// FilterTrackedUsers finds all the user IDs out of the given ones for which the database contains identity information.
func (store *SQLCryptoStore) FilterTrackedUsers(users []id.UserID) ([]id.UserID, error) {
	var rows dbutil.Rows
	var err error
	if store.DB.Dialect == dbutil.Postgres && PostgresArrayWrapper != nil {
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
		return users, err
	}
	var ptr int
	for rows.Next() {
		err = rows.Scan(&users[ptr])
		if err != nil {
			return users, err
		} else {
			ptr++
		}
	}
	return users[:ptr], nil
}

// PutCrossSigningKey stores a cross-signing key of some user along with its usage.
func (store *SQLCryptoStore) PutCrossSigningKey(userID id.UserID, usage id.CrossSigningUsage, key id.Ed25519) error {
	_, err := store.DB.Exec(`
		INSERT INTO crypto_cross_signing_keys (user_id, usage, key, first_seen_key) VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id, usage) DO UPDATE SET key=excluded.key
	`, userID, usage, key, key)
	return err
}

// GetCrossSigningKeys retrieves a user's stored cross-signing keys.
func (store *SQLCryptoStore) GetCrossSigningKeys(userID id.UserID) (map[id.CrossSigningUsage]id.CrossSigningKey, error) {
	rows, err := store.DB.Query("SELECT usage, key, first_seen_key FROM crypto_cross_signing_keys WHERE user_id=$1", userID)
	if err != nil {
		return nil, err
	}
	data := make(map[id.CrossSigningUsage]id.CrossSigningKey)
	for rows.Next() {
		var usage id.CrossSigningUsage
		var key, first id.Ed25519
		err = rows.Scan(&usage, &key, &first)
		if err != nil {
			return nil, err
		}
		data[usage] = id.CrossSigningKey{Key: key, First: first}
	}

	return data, nil
}

// PutSignature stores a signature of a cross-signing or device key along with the signer's user ID and key.
func (store *SQLCryptoStore) PutSignature(signedUserID id.UserID, signedKey id.Ed25519, signerUserID id.UserID, signerKey id.Ed25519, signature string) error {
	_, err := store.DB.Exec(`
		INSERT INTO crypto_cross_signing_signatures (signed_user_id, signed_key, signer_user_id, signer_key, signature) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (signed_user_id, signed_key, signer_user_id, signer_key) DO UPDATE SET signature=excluded.signature
	`, signedUserID, signedKey, signerUserID, signerKey, signature)
	return err
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
		err = rows.Scan(&signerKey, &signature)
		if err != nil {
			return nil, err
		}
		data[signerKey] = signature
	}

	return data, nil
}

// IsKeySignedBy returns whether a cross-signing or device key is signed by the given signer.
func (store *SQLCryptoStore) IsKeySignedBy(signedUserID id.UserID, signedKey id.Ed25519, signerUserID id.UserID, signerKey id.Ed25519) (isSigned bool, err error) {
	q := `SELECT EXISTS(
		SELECT 1 FROM crypto_cross_signing_signatures
		WHERE signed_user_id=$1 AND signed_key=$2 AND signer_user_id=$3 AND signer_key=$4
	)`
	err = store.DB.QueryRow(q, signedUserID, signedKey, signerUserID, signerKey).Scan(&isSigned)
	return
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
