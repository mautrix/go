// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package database

import (
	"context"
	"database/sql"
	"time"

	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/id"
)

type MessageQuery struct {
	BridgeID networkid.BridgeID
	*dbutil.QueryHelper[*Message]
}

type StandardMessageMetadata struct {
	SenderMXID id.UserID `json:"sender_mxid,omitempty"`
	EditCount  int       `json:"edit_count,omitempty"`
}

type MessageMetadata struct {
	StandardMessageMetadata
	Extra map[string]any
}

func (mm *MessageMetadata) UnmarshalJSON(data []byte) error {
	return unmarshalMerge(data, &mm.StandardMessageMetadata, &mm.Extra)
}

func (mm *MessageMetadata) MarshalJSON() ([]byte, error) {
	return marshalMerge(&mm.StandardMessageMetadata, mm.Extra)
}

type Message struct {
	RowID    int64
	BridgeID networkid.BridgeID
	ID       networkid.MessageID
	PartID   networkid.PartID
	MXID     id.EventID

	Room      networkid.PortalKey
	SenderID  networkid.UserID
	Timestamp time.Time

	RelatesToRowID int64

	Metadata MessageMetadata
}

func newMessage(_ *dbutil.QueryHelper[*Message]) *Message {
	return &Message{}
}

const (
	getMessageBaseQuery = `
		SELECT rowid, bridge_id, id, part_id, mxid, room_id, room_receiver, sender_id, timestamp, relates_to, metadata FROM message
	`
	getAllMessagePartsByIDQuery  = getMessageBaseQuery + `WHERE bridge_id=$1 AND id=$2`
	getMessagePartByIDQuery      = getMessageBaseQuery + `WHERE bridge_id=$1 AND id=$2 AND part_id=$3`
	getMessagePartByRowIDQuery   = getMessageBaseQuery + `WHERE bridge_id=$1 AND rowid=$2`
	getMessageByMXIDQuery        = getMessageBaseQuery + `WHERE bridge_id=$1 AND mxid=$2`
	getLastMessagePartByIDQuery  = getMessageBaseQuery + `WHERE bridge_id=$1 AND id=$2 ORDER BY part_id DESC LIMIT 1`
	getFirstMessagePartByIDQuery = getMessageBaseQuery + `WHERE bridge_id=$1 AND id=$2 ORDER BY part_id ASC LIMIT 1`
	getMessagesBetweenTimeQuery  = getMessageBaseQuery + `WHERE bridge_id=$1 AND room_id=$2 AND room_receiver=$3 AND timestamp>$4 AND timestamp<=$5`
	insertMessageQuery           = `
		INSERT INTO message (bridge_id, id, part_id, mxid, room_id, room_receiver, sender_id, timestamp, relates_to, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING rowid
	`
	updateMessageQuery = `
		UPDATE message SET id=$2, part_id=$3, mxid=$4, room_id=$5, room_receiver=$6, sender_id=$7, timestamp=$8, relates_to=$9, metadata=$10
		WHERE bridge_id=$1 AND rowid=$11
	`
	deleteAllMessagePartsByIDQuery = `
		DELETE FROM message WHERE bridge_id=$1 AND id=$2
	`
	deleteMessagePartByRowIDQuery = `
		DELETE FROM message WHERE bridge_id=$1 AND rowid=$2
	`
)

func (mq *MessageQuery) GetAllPartsByID(ctx context.Context, id networkid.MessageID) ([]*Message, error) {
	return mq.QueryMany(ctx, getAllMessagePartsByIDQuery, mq.BridgeID, id)
}

func (mq *MessageQuery) GetPartByID(ctx context.Context, id networkid.MessageID, partID networkid.PartID) (*Message, error) {
	return mq.QueryOne(ctx, getMessagePartByIDQuery, mq.BridgeID, id, partID)
}

func (mq *MessageQuery) GetPartByMXID(ctx context.Context, mxid id.EventID) (*Message, error) {
	return mq.QueryOne(ctx, getMessageByMXIDQuery, mq.BridgeID, mxid)
}

func (mq *MessageQuery) GetLastPartByID(ctx context.Context, id networkid.MessageID) (*Message, error) {
	return mq.QueryOne(ctx, getLastMessagePartByIDQuery, mq.BridgeID, id)
}

func (mq *MessageQuery) GetFirstPartByID(ctx context.Context, id networkid.MessageID) (*Message, error) {
	return mq.QueryOne(ctx, getFirstMessagePartByIDQuery, mq.BridgeID, id)
}

func (mq *MessageQuery) GetByRowID(ctx context.Context, rowID int64) (*Message, error) {
	return mq.QueryOne(ctx, getMessagePartByRowIDQuery, mq.BridgeID, rowID)
}

func (mq *MessageQuery) GetFirstOrSpecificPartByID(ctx context.Context, id networkid.MessageOptionalPartID) (*Message, error) {
	if id.PartID == nil {
		return mq.GetFirstPartByID(ctx, id.MessageID)
	} else {
		return mq.GetPartByID(ctx, id.MessageID, *id.PartID)
	}
}

func (mq *MessageQuery) GetMessagesBetweenTimeQuery(ctx context.Context, portal networkid.PortalKey, start, end time.Time) ([]*Message, error) {
	return mq.QueryMany(ctx, getMessagesBetweenTimeQuery, mq.BridgeID, portal.ID, portal.Receiver, start.UnixNano(), end.UnixNano())
}

func (mq *MessageQuery) Insert(ctx context.Context, msg *Message) error {
	ensureBridgeIDMatches(&msg.BridgeID, mq.BridgeID)
	return mq.GetDB().QueryRow(ctx, insertMessageQuery, msg.sqlVariables()...).Scan(&msg.RowID)
}

func (mq *MessageQuery) Update(ctx context.Context, msg *Message) error {
	ensureBridgeIDMatches(&msg.BridgeID, mq.BridgeID)
	return mq.Exec(ctx, updateMessageQuery, msg.updateSQLVariables()...)
}

func (mq *MessageQuery) DeleteAllParts(ctx context.Context, id networkid.MessageID) error {
	return mq.Exec(ctx, deleteAllMessagePartsByIDQuery, mq.BridgeID, id)
}

func (mq *MessageQuery) Delete(ctx context.Context, rowID int64) error {
	return mq.Exec(ctx, deleteMessagePartByRowIDQuery, mq.BridgeID, rowID)
}

func (m *Message) Scan(row dbutil.Scannable) (*Message, error) {
	var timestamp int64
	var relatesTo sql.NullInt64
	err := row.Scan(
		&m.RowID, &m.BridgeID, &m.ID, &m.PartID, &m.MXID, &m.Room.ID, &m.Room.Receiver, &m.SenderID,
		&timestamp, &relatesTo, dbutil.JSON{Data: &m.Metadata},
	)
	if err != nil {
		return nil, err
	}
	if m.Metadata.Extra == nil {
		m.Metadata.Extra = make(map[string]any)
	}
	m.Timestamp = time.Unix(0, timestamp)
	m.RelatesToRowID = relatesTo.Int64
	return m, nil
}

func (m *Message) sqlVariables() []any {
	if m.Metadata.Extra == nil {
		m.Metadata.Extra = make(map[string]any)
	}
	return []any{
		m.BridgeID, m.ID, m.PartID, m.MXID, m.Room.ID, m.Room.Receiver, m.SenderID,
		m.Timestamp.UnixNano(), dbutil.NumPtr(m.RelatesToRowID), dbutil.JSON{Data: &m.Metadata},
	}
}

func (m *Message) updateSQLVariables() []any {
	return append(m.sqlVariables(), m.RowID)
}
