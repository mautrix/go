// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"strings"
	"time"

	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/id"
)

type MessageQuery struct {
	BridgeID networkid.BridgeID
	MetaType MetaTypeCreator
	*dbutil.QueryHelper[*Message]
}

type Message struct {
	RowID    int64
	BridgeID networkid.BridgeID
	ID       networkid.MessageID
	PartID   networkid.PartID
	MXID     id.EventID

	Room             networkid.PortalKey
	SenderID         networkid.UserID
	SenderMXID       id.UserID
	Timestamp        time.Time
	EditCount        int
	IsDoublePuppeted bool

	ThreadRoot networkid.MessageID
	ReplyTo    networkid.MessageOptionalPartID

	SendTxnID networkid.RawTransactionID

	Metadata any
}

const (
	getMessageBaseQuery = `
		SELECT rowid, bridge_id, id, part_id, mxid, room_id, room_receiver, sender_id, sender_mxid,
		       timestamp, edit_count, double_puppeted, thread_root_id, reply_to_id, reply_to_part_id,
			   send_txn_id, metadata
		FROM message
	`
	getAllMessagePartsByIDQuery  = getMessageBaseQuery + `WHERE bridge_id=$1 AND (room_receiver=$2 OR room_receiver='') AND id=$3`
	getMessagePartByIDQuery      = getMessageBaseQuery + `WHERE bridge_id=$1 AND (room_receiver=$2 OR room_receiver='') AND id=$3 AND part_id=$4`
	getMessagePartByRowIDQuery   = getMessageBaseQuery + `WHERE bridge_id=$1 AND rowid=$2`
	getMessageByMXIDQuery        = getMessageBaseQuery + `WHERE bridge_id=$1 AND mxid=$2`
	getMessageByTxnIDQuery       = getMessageBaseQuery + `WHERE bridge_id=$1 AND (room_receiver=$2 OR room_receiver='') AND (mxid=$3 OR send_txn_id=$4)`
	getLastMessagePartByIDQuery  = getMessageBaseQuery + `WHERE bridge_id=$1 AND (room_receiver=$2 OR room_receiver='') AND id=$3 ORDER BY part_id DESC LIMIT 1`
	getFirstMessagePartByIDQuery = getMessageBaseQuery + `WHERE bridge_id=$1 AND (room_receiver=$2 OR room_receiver='') AND id=$3 ORDER BY part_id ASC LIMIT 1`
	getMessagesBetweenTimeQuery  = getMessageBaseQuery + `WHERE bridge_id=$1 AND room_id=$2 AND room_receiver=$3 AND timestamp>$4 AND timestamp<=$5`
	getOldestMessageInPortal     = getMessageBaseQuery + `WHERE bridge_id=$1 AND room_id=$2 AND room_receiver=$3 ORDER BY timestamp ASC, part_id ASC LIMIT 1`
	getFirstMessageInThread      = getMessageBaseQuery + `WHERE bridge_id=$1 AND room_id=$2 AND room_receiver=$3 AND (id=$4 OR thread_root_id=$4) ORDER BY timestamp ASC, part_id ASC LIMIT 1`
	getLastMessageInThread       = getMessageBaseQuery + `WHERE bridge_id=$1 AND room_id=$2 AND room_receiver=$3 AND (id=$4 OR thread_root_id=$4) ORDER BY timestamp DESC, part_id DESC LIMIT 1`
	getLastNInPortal             = getMessageBaseQuery + `WHERE bridge_id=$1 AND room_id=$2 AND room_receiver=$3 ORDER BY timestamp DESC, part_id DESC LIMIT $4`

	getLastMessagePartAtOrBeforeTimeQuery        = getMessageBaseQuery + `WHERE bridge_id = $1 AND room_id=$2 AND room_receiver=$3 AND timestamp<=$4 ORDER BY timestamp DESC, part_id DESC LIMIT 1`
	getLastNonFakeMessagePartAtOrBeforeTimeQuery = getMessageBaseQuery + `WHERE bridge_id = $1 AND room_id=$2 AND room_receiver=$3 AND timestamp<=$4 AND mxid NOT LIKE '~fake:%' ORDER BY timestamp DESC, part_id DESC LIMIT 1`

	countMessagesInPortalQuery = `
		SELECT COUNT(*) FROM message WHERE bridge_id=$1 AND room_id=$2 AND room_receiver=$3
	`

	insertMessageQuery = `
		INSERT INTO message (
			bridge_id, id, part_id, mxid, room_id, room_receiver, sender_id, sender_mxid,
			timestamp, edit_count, double_puppeted, thread_root_id, reply_to_id, reply_to_part_id,
			send_txn_id, metadata
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		RETURNING rowid
	`
	updateMessageQuery = `
		UPDATE message SET id=$2, part_id=$3, mxid=$4, room_id=$5, room_receiver=$6, sender_id=$7, sender_mxid=$8,
		                   timestamp=$9, edit_count=$10, double_puppeted=$11, thread_root_id=$12, reply_to_id=$13,
                           reply_to_part_id=$14, send_txn_id=$15, metadata=$16
		WHERE bridge_id=$1 AND rowid=$17
	`
	deleteAllMessagePartsByIDQuery = `
		DELETE FROM message WHERE bridge_id=$1 AND (room_receiver=$2 OR room_receiver='') AND id=$3
	`
	deleteMessagePartByRowIDQuery = `
		DELETE FROM message WHERE bridge_id=$1 AND rowid=$2
	`
)

func (mq *MessageQuery) GetAllPartsByID(ctx context.Context, receiver networkid.UserLoginID, id networkid.MessageID) ([]*Message, error) {
	return mq.QueryMany(ctx, getAllMessagePartsByIDQuery, mq.BridgeID, receiver, id)
}

func (mq *MessageQuery) GetPartByID(ctx context.Context, receiver networkid.UserLoginID, id networkid.MessageID, partID networkid.PartID) (*Message, error) {
	return mq.QueryOne(ctx, getMessagePartByIDQuery, mq.BridgeID, receiver, id, partID)
}

func (mq *MessageQuery) GetPartByMXID(ctx context.Context, mxid id.EventID) (*Message, error) {
	return mq.QueryOne(ctx, getMessageByMXIDQuery, mq.BridgeID, mxid)
}

func (mq *MessageQuery) GetPartByTxnID(ctx context.Context, receiver networkid.UserLoginID, mxid id.EventID, txnID networkid.RawTransactionID) (*Message, error) {
	return mq.QueryOne(ctx, getMessageByTxnIDQuery, mq.BridgeID, receiver, mxid, txnID)
}

func (mq *MessageQuery) GetLastPartByID(ctx context.Context, receiver networkid.UserLoginID, id networkid.MessageID) (*Message, error) {
	return mq.QueryOne(ctx, getLastMessagePartByIDQuery, mq.BridgeID, receiver, id)
}

func (mq *MessageQuery) GetFirstPartByID(ctx context.Context, receiver networkid.UserLoginID, id networkid.MessageID) (*Message, error) {
	return mq.QueryOne(ctx, getFirstMessagePartByIDQuery, mq.BridgeID, receiver, id)
}

func (mq *MessageQuery) GetByRowID(ctx context.Context, rowID int64) (*Message, error) {
	return mq.QueryOne(ctx, getMessagePartByRowIDQuery, mq.BridgeID, rowID)
}

func (mq *MessageQuery) GetFirstOrSpecificPartByID(ctx context.Context, receiver networkid.UserLoginID, id networkid.MessageOptionalPartID) (*Message, error) {
	if id.PartID == nil {
		return mq.GetFirstPartByID(ctx, receiver, id.MessageID)
	} else {
		return mq.GetPartByID(ctx, receiver, id.MessageID, *id.PartID)
	}
}

func (mq *MessageQuery) GetLastPartAtOrBeforeTime(ctx context.Context, portal networkid.PortalKey, maxTS time.Time) (*Message, error) {
	return mq.QueryOne(ctx, getLastMessagePartAtOrBeforeTimeQuery, mq.BridgeID, portal.ID, portal.Receiver, maxTS.UnixNano())
}

func (mq *MessageQuery) GetLastNonFakePartAtOrBeforeTime(ctx context.Context, portal networkid.PortalKey, maxTS time.Time) (*Message, error) {
	return mq.QueryOne(ctx, getLastNonFakeMessagePartAtOrBeforeTimeQuery, mq.BridgeID, portal.ID, portal.Receiver, maxTS.UnixNano())
}

func (mq *MessageQuery) GetMessagesBetweenTimeQuery(ctx context.Context, portal networkid.PortalKey, start, end time.Time) ([]*Message, error) {
	return mq.QueryMany(ctx, getMessagesBetweenTimeQuery, mq.BridgeID, portal.ID, portal.Receiver, start.UnixNano(), end.UnixNano())
}

func (mq *MessageQuery) GetFirstPortalMessage(ctx context.Context, portal networkid.PortalKey) (*Message, error) {
	return mq.QueryOne(ctx, getOldestMessageInPortal, mq.BridgeID, portal.ID, portal.Receiver)
}

func (mq *MessageQuery) GetFirstThreadMessage(ctx context.Context, portal networkid.PortalKey, threadRoot networkid.MessageID) (*Message, error) {
	return mq.QueryOne(ctx, getFirstMessageInThread, mq.BridgeID, portal.ID, portal.Receiver, threadRoot)
}

func (mq *MessageQuery) GetLastThreadMessage(ctx context.Context, portal networkid.PortalKey, threadRoot networkid.MessageID) (*Message, error) {
	return mq.QueryOne(ctx, getLastMessageInThread, mq.BridgeID, portal.ID, portal.Receiver, threadRoot)
}

func (mq *MessageQuery) GetLastNInPortal(ctx context.Context, portal networkid.PortalKey, n int) ([]*Message, error) {
	return mq.QueryMany(ctx, getLastNInPortal, mq.BridgeID, portal.ID, portal.Receiver, n)
}

func (mq *MessageQuery) Insert(ctx context.Context, msg *Message) error {
	ensureBridgeIDMatches(&msg.BridgeID, mq.BridgeID)
	return mq.GetDB().QueryRow(ctx, insertMessageQuery, msg.ensureHasMetadata(mq.MetaType).sqlVariables()...).Scan(&msg.RowID)
}

func (mq *MessageQuery) Update(ctx context.Context, msg *Message) error {
	ensureBridgeIDMatches(&msg.BridgeID, mq.BridgeID)
	return mq.Exec(ctx, updateMessageQuery, msg.ensureHasMetadata(mq.MetaType).updateSQLVariables()...)
}

func (mq *MessageQuery) DeleteAllParts(ctx context.Context, receiver networkid.UserLoginID, id networkid.MessageID) error {
	return mq.Exec(ctx, deleteAllMessagePartsByIDQuery, mq.BridgeID, receiver, id)
}

func (mq *MessageQuery) Delete(ctx context.Context, rowID int64) error {
	return mq.Exec(ctx, deleteMessagePartByRowIDQuery, mq.BridgeID, rowID)
}

func (mq *MessageQuery) CountMessagesInPortal(ctx context.Context, key networkid.PortalKey) (count int, err error) {
	err = mq.GetDB().QueryRow(ctx, countMessagesInPortalQuery, mq.BridgeID, key.ID, key.Receiver).Scan(&count)
	return
}

func (m *Message) Scan(row dbutil.Scannable) (*Message, error) {
	var timestamp int64
	var threadRootID, replyToID, replyToPartID, sendTxnID sql.NullString
	var doublePuppeted sql.NullBool
	err := row.Scan(
		&m.RowID, &m.BridgeID, &m.ID, &m.PartID, &m.MXID, &m.Room.ID, &m.Room.Receiver, &m.SenderID, &m.SenderMXID,
		&timestamp, &m.EditCount, &doublePuppeted, &threadRootID, &replyToID, &replyToPartID, &sendTxnID,
		dbutil.JSON{Data: m.Metadata},
	)
	if err != nil {
		return nil, err
	}
	m.Timestamp = time.Unix(0, timestamp)
	m.ThreadRoot = networkid.MessageID(threadRootID.String)
	m.IsDoublePuppeted = doublePuppeted.Valid
	if replyToID.Valid {
		m.ReplyTo.MessageID = networkid.MessageID(replyToID.String)
		if replyToPartID.Valid {
			m.ReplyTo.PartID = (*networkid.PartID)(&replyToPartID.String)
		}
	}
	if sendTxnID.Valid {
		m.SendTxnID = networkid.RawTransactionID(sendTxnID.String)
	}
	return m, nil
}

func (m *Message) ensureHasMetadata(metaType MetaTypeCreator) *Message {
	if m.Metadata == nil {
		m.Metadata = metaType()
	}
	return m
}

func (m *Message) sqlVariables() []any {
	return []any{
		m.BridgeID, m.ID, m.PartID, m.MXID, m.Room.ID, m.Room.Receiver, m.SenderID, m.SenderMXID,
		m.Timestamp.UnixNano(), m.EditCount, m.IsDoublePuppeted, dbutil.StrPtr(m.ThreadRoot),
		dbutil.StrPtr(m.ReplyTo.MessageID), m.ReplyTo.PartID, dbutil.StrPtr(m.SendTxnID),
		dbutil.JSON{Data: m.Metadata},
	}
}

func (m *Message) updateSQLVariables() []any {
	return append(m.sqlVariables(), m.RowID)
}

const FakeMXIDPrefix = "~fake:"
const TxnMXIDPrefix = "~txn:"
const NetworkTxnMXIDPrefix = TxnMXIDPrefix + "network:"
const RandomTxnMXIDPrefix = TxnMXIDPrefix + "random:"

func (m *Message) SetFakeMXID() {
	hash := sha256.Sum256([]byte(m.ID))
	m.MXID = id.EventID(FakeMXIDPrefix + base64.RawURLEncoding.EncodeToString(hash[:]))
}

func (m *Message) HasFakeMXID() bool {
	return strings.HasPrefix(m.MXID.String(), FakeMXIDPrefix)
}
