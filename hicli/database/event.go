// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package database

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/tidwall/gjson"
	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/exgjson"
	"golang.org/x/net/context"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

const (
	getEventBaseQuery = `
		SELECT rowid, room_id, event_id, sender, type, state_key, timestamp, content, decrypted, decrypted_type, unsigned,
		       redacted_by, relates_to, megolm_session_id, decryption_error
		FROM event
	`
	getFailedEventsByMegolmSessionID = getEventBaseQuery + `WHERE room_id = $1 AND megolm_session_id = $2 AND decryption_error IS NOT NULL`
	upsertEventQuery                 = `
		INSERT INTO event (room_id, event_id, sender, type, state_key, timestamp, content, decrypted, decrypted_type, unsigned, redacted_by, relates_to, megolm_session_id, decryption_error)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (event_id) DO UPDATE
			SET decrypted=COALESCE(event.decrypted, excluded.decrypted),
			    decrypted_type=COALESCE(event.decrypted_type, excluded.decrypted_type),
			    redacted_by=COALESCE(event.redacted_by, excluded.redacted_by),
			    decryption_error=CASE WHEN COALESCE(event.decrypted, excluded.decrypted) IS NULL THEN COALESCE(excluded.decryption_error, event.decryption_error) END
		RETURNING rowid
	`
	updateEventDecryptedQuery = `UPDATE event SET decrypted = $1, decrypted_type = $2, decryption_error = NULL WHERE rowid = $3`
)

type EventQuery struct {
	*dbutil.QueryHelper[*Event]
}

func (eq *EventQuery) GetFailedByMegolmSessionID(ctx context.Context, roomID id.RoomID, sessionID id.SessionID) ([]*Event, error) {
	return eq.QueryMany(ctx, getFailedEventsByMegolmSessionID, roomID, sessionID)
}

func (eq *EventQuery) Upsert(ctx context.Context, evt *Event) (rowID int64, err error) {
	err = eq.GetDB().QueryRow(ctx, upsertEventQuery, evt.sqlVariables()...).Scan(&rowID)
	return
}

func (eq *EventQuery) UpdateDecrypted(ctx context.Context, rowID int64, decrypted json.RawMessage, decryptedType string) error {
	return eq.Exec(ctx, updateEventDecryptedQuery, unsafeJSONString(decrypted), decryptedType, rowID)
}

type Event struct {
	RowID int64

	RoomID    id.RoomID
	ID        id.EventID
	Sender    id.UserID
	Type      string
	StateKey  *string
	Timestamp time.Time

	Content       json.RawMessage
	Decrypted     json.RawMessage
	DecryptedType string
	Unsigned      json.RawMessage

	RedactedBy id.EventID
	RelatesTo  id.EventID

	MegolmSessionID id.SessionID
	DecryptionError string
}

func MautrixToEvent(evt *event.Event) *Event {
	dbEvt := &Event{
		RoomID:          evt.RoomID,
		ID:              evt.ID,
		Sender:          evt.Sender,
		Type:            evt.Type.Type,
		StateKey:        evt.StateKey,
		Timestamp:       time.UnixMilli(evt.Timestamp),
		Content:         evt.Content.VeryRaw,
		RelatesTo:       getRelatesTo(evt),
		MegolmSessionID: getMegolmSessionID(evt),
	}
	dbEvt.Unsigned, _ = json.Marshal(&evt.Unsigned)
	if evt.Unsigned.RedactedBecause != nil {
		dbEvt.RedactedBy = evt.Unsigned.RedactedBecause.ID
	}
	return dbEvt
}

func (e *Event) AsRawMautrix() *event.Event {
	evt := &event.Event{
		RoomID:    e.RoomID,
		ID:        e.ID,
		Sender:    e.Sender,
		Type:      event.Type{Type: e.Type, Class: event.MessageEventType},
		StateKey:  e.StateKey,
		Timestamp: e.Timestamp.UnixMilli(),
		Content:   event.Content{VeryRaw: e.Content},
	}
	if e.Decrypted != nil {
		evt.Content.VeryRaw = e.Decrypted
		evt.Type.Type = e.DecryptedType
		evt.Mautrix.WasEncrypted = true
	}
	if e.StateKey != nil {
		evt.Type.Class = event.StateEventType
	}
	_ = json.Unmarshal(e.Unsigned, &evt.Unsigned)
	return evt
}

func (e *Event) Scan(row dbutil.Scannable) (*Event, error) {
	var timestamp int64
	var redactedBy, relatesTo, megolmSessionID, decryptionError, decryptedType sql.NullString
	err := row.Scan(
		&e.RowID,
		&e.RoomID,
		&e.ID,
		&e.Sender,
		&e.Type,
		&e.StateKey,
		&timestamp,
		(*[]byte)(&e.Content),
		(*[]byte)(&e.Decrypted),
		&decryptedType,
		(*[]byte)(&e.Unsigned),
		&redactedBy,
		&relatesTo,
		&megolmSessionID,
		&decryptionError,
	)
	if err != nil {
		return nil, err
	}
	e.Timestamp = time.UnixMilli(timestamp)
	e.RedactedBy = id.EventID(redactedBy.String)
	e.RelatesTo = id.EventID(relatesTo.String)
	e.MegolmSessionID = id.SessionID(megolmSessionID.String)
	e.DecryptedType = decryptedType.String
	e.DecryptionError = decryptionError.String
	return e, nil
}

var relatesToPath = exgjson.Path("m.relates_to", "event_id")

func getRelatesTo(evt *event.Event) id.EventID {
	res := gjson.GetBytes(evt.Content.VeryRaw, relatesToPath)
	if res.Exists() && res.Type == gjson.String {
		return id.EventID(res.Str)
	}
	return ""
}

func getMegolmSessionID(evt *event.Event) id.SessionID {
	if evt.Type != event.EventEncrypted {
		return ""
	}
	res := gjson.GetBytes(evt.Content.VeryRaw, "session_id")
	if res.Exists() && res.Type == gjson.String {
		return id.SessionID(res.Str)
	}
	return ""
}

func (e *Event) sqlVariables() []any {
	return []any{
		e.RoomID,
		e.ID,
		e.Sender,
		e.Type,
		e.StateKey,
		e.Timestamp.UnixMilli(),
		unsafeJSONString(e.Content),
		unsafeJSONString(e.Decrypted),
		dbutil.StrPtr(e.DecryptedType),
		unsafeJSONString(e.Unsigned),
		dbutil.StrPtr(e.RedactedBy),
		dbutil.StrPtr(e.RelatesTo),
		dbutil.StrPtr(e.MegolmSessionID),
		dbutil.StrPtr(e.DecryptionError),
	}
}
