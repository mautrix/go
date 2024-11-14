// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package database

import (
	"context"
	"time"

	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/id"
)

type ReactionQuery struct {
	BridgeID networkid.BridgeID
	MetaType MetaTypeCreator
	*dbutil.QueryHelper[*Reaction]
}

type Reaction struct {
	BridgeID      networkid.BridgeID
	Room          networkid.PortalKey
	MessageID     networkid.MessageID
	MessagePartID networkid.PartID
	SenderID      networkid.UserID
	SenderMXID    id.UserID
	EmojiID       networkid.EmojiID
	MXID          id.EventID

	Timestamp time.Time
	Emoji     string
	Metadata  any
}

const (
	getReactionBaseQuery = `
		SELECT bridge_id, message_id, message_part_id, sender_id, sender_mxid, emoji_id, emoji, room_id, room_receiver, mxid, timestamp, metadata FROM reaction
	`
	getReactionByIDQuery                   = getReactionBaseQuery + `WHERE bridge_id=$1 AND room_receiver=$2 AND message_id=$3 AND message_part_id=$4 AND sender_id=$5 AND emoji_id=$6`
	getReactionByIDWithoutMessagePartQuery = getReactionBaseQuery + `WHERE bridge_id=$1 AND room_receiver=$2 AND message_id=$3 AND sender_id=$4 AND emoji_id=$5 ORDER BY message_part_id ASC LIMIT 1`
	getAllReactionsToMessageBySenderQuery  = getReactionBaseQuery + `WHERE bridge_id=$1 AND room_receiver=$2 AND message_id=$3 AND sender_id=$4 ORDER BY timestamp DESC`
	getAllReactionsToMessageQuery          = getReactionBaseQuery + `WHERE bridge_id=$1 AND room_receiver=$2 AND message_id=$3`
	getAllReactionsToMessagePartQuery      = getReactionBaseQuery + `WHERE bridge_id=$1 AND room_receiver=$2 AND message_id=$3 AND message_part_id=$4`
	getReactionByMXIDQuery                 = getReactionBaseQuery + `WHERE bridge_id=$1 AND mxid=$2`
	upsertReactionQuery                    = `
		INSERT INTO reaction (bridge_id, message_id, message_part_id, sender_id, sender_mxid, emoji_id, emoji, room_id, room_receiver, mxid, timestamp, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (bridge_id, room_receiver, message_id, message_part_id, sender_id, emoji_id)
		DO UPDATE SET sender_mxid=excluded.sender_mxid, mxid=excluded.mxid, timestamp=excluded.timestamp, emoji=excluded.emoji, metadata=excluded.metadata
	`
	deleteReactionQuery = `
		DELETE FROM reaction WHERE bridge_id=$1 AND room_receiver=$2 AND message_id=$3 AND message_part_id=$4 AND sender_id=$5 AND emoji_id=$6
	`
)

func (rq *ReactionQuery) GetByID(ctx context.Context, receiver networkid.UserLoginID, messageID networkid.MessageID, messagePartID networkid.PartID, senderID networkid.UserID, emojiID networkid.EmojiID) (*Reaction, error) {
	return rq.QueryOne(ctx, getReactionByIDQuery, rq.BridgeID, receiver, messageID, messagePartID, senderID, emojiID)
}

func (rq *ReactionQuery) GetByIDWithoutMessagePart(ctx context.Context, receiver networkid.UserLoginID, messageID networkid.MessageID, senderID networkid.UserID, emojiID networkid.EmojiID) (*Reaction, error) {
	return rq.QueryOne(ctx, getReactionByIDWithoutMessagePartQuery, rq.BridgeID, receiver, messageID, senderID, emojiID)
}

func (rq *ReactionQuery) GetAllToMessageBySender(ctx context.Context, receiver networkid.UserLoginID, messageID networkid.MessageID, senderID networkid.UserID) ([]*Reaction, error) {
	return rq.QueryMany(ctx, getAllReactionsToMessageBySenderQuery, rq.BridgeID, receiver, messageID, senderID)
}

func (rq *ReactionQuery) GetAllToMessage(ctx context.Context, receiver networkid.UserLoginID, messageID networkid.MessageID) ([]*Reaction, error) {
	return rq.QueryMany(ctx, getAllReactionsToMessageQuery, rq.BridgeID, receiver, messageID)
}

func (rq *ReactionQuery) GetAllToMessagePart(ctx context.Context, receiver networkid.UserLoginID, messageID networkid.MessageID, partID networkid.PartID) ([]*Reaction, error) {
	return rq.QueryMany(ctx, getAllReactionsToMessagePartQuery, rq.BridgeID, receiver, messageID, partID)
}

func (rq *ReactionQuery) GetByMXID(ctx context.Context, mxid id.EventID) (*Reaction, error) {
	return rq.QueryOne(ctx, getReactionByMXIDQuery, rq.BridgeID, mxid)
}

func (rq *ReactionQuery) Upsert(ctx context.Context, reaction *Reaction) error {
	ensureBridgeIDMatches(&reaction.BridgeID, rq.BridgeID)
	return rq.Exec(ctx, upsertReactionQuery, reaction.ensureHasMetadata(rq.MetaType).sqlVariables()...)
}

func (rq *ReactionQuery) Delete(ctx context.Context, reaction *Reaction) error {
	ensureBridgeIDMatches(&reaction.BridgeID, rq.BridgeID)
	return rq.Exec(ctx, deleteReactionQuery, reaction.BridgeID, reaction.Room.Receiver, reaction.MessageID, reaction.MessagePartID, reaction.SenderID, reaction.EmojiID)
}

func (r *Reaction) Scan(row dbutil.Scannable) (*Reaction, error) {
	var timestamp int64
	err := row.Scan(
		&r.BridgeID, &r.MessageID, &r.MessagePartID, &r.SenderID, &r.SenderMXID, &r.EmojiID, &r.Emoji,
		&r.Room.ID, &r.Room.Receiver, &r.MXID, &timestamp, dbutil.JSON{Data: r.Metadata},
	)
	if err != nil {
		return nil, err
	}
	r.Timestamp = time.Unix(0, timestamp)
	return r, nil
}

func (r *Reaction) ensureHasMetadata(metaType MetaTypeCreator) *Reaction {
	if r.Metadata == nil {
		r.Metadata = metaType()
	}
	return r
}

func (r *Reaction) sqlVariables() []any {
	return []any{
		r.BridgeID, r.MessageID, r.MessagePartID, r.SenderID, r.SenderMXID, r.EmojiID, r.Emoji,
		r.Room.ID, r.Room.Receiver, r.MXID, r.Timestamp.UnixNano(), dbutil.JSON{Data: r.Metadata},
	}
}
