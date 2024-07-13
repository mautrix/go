// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package database

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/id"
)

type RoomType string

const (
	RoomTypeDefault RoomType = ""
	RoomTypeDM      RoomType = "dm"
	RoomTypeGroupDM RoomType = "group_dm"
	RoomTypeSpace   RoomType = "space"
)

type PortalQuery struct {
	BridgeID networkid.BridgeID
	MetaType MetaTypeCreator
	*dbutil.QueryHelper[*Portal]
}

type Portal struct {
	BridgeID networkid.BridgeID
	networkid.PortalKey
	MXID id.RoomID

	ParentID     networkid.PortalID
	RelayLoginID networkid.UserLoginID
	Name         string
	Topic        string
	AvatarID     networkid.AvatarID
	AvatarHash   [32]byte
	AvatarMXC    id.ContentURIString
	NameSet      bool
	TopicSet     bool
	AvatarSet    bool
	InSpace      bool
	RoomType     RoomType
	Disappear    DisappearingSetting
	Metadata     any
}

const (
	getPortalBaseQuery = `
		SELECT bridge_id, id, receiver, mxid, parent_id, relay_login_id,
		       name, topic, avatar_id, avatar_hash, avatar_mxc,
		       name_set, topic_set, avatar_set, in_space,
		       room_type, disappear_type, disappear_timer,
		       metadata
		FROM portal
	`
	getPortalByIDQuery                      = getPortalBaseQuery + `WHERE bridge_id=$1 AND id=$2 AND receiver=$3`
	getPortalByIDWithUncertainReceiverQuery = getPortalBaseQuery + `WHERE bridge_id=$1 AND id=$2 AND (receiver=$3 OR receiver='')`
	getPortalByMXIDQuery                    = getPortalBaseQuery + `WHERE bridge_id=$1 AND mxid=$2`
	getChildPortalsQuery                    = getPortalBaseQuery + `WHERE bridge_id=$1 AND parent_id=$2`

	findPortalReceiverQuery = `SELECT id, receiver FROM portal WHERE bridge_id=$1 AND id=$2 AND (receiver=$3 OR receiver='') LIMIT 1`

	insertPortalQuery = `
		INSERT INTO portal (
			bridge_id, id, receiver, mxid,
			parent_id, relay_login_id,
			name, topic, avatar_id, avatar_hash, avatar_mxc,
			name_set, avatar_set, topic_set, in_space,
			room_type, disappear_type, disappear_timer,
			metadata, relay_bridge_id
		) VALUES (
			$1, $2, $3, $4, $5, cast($6 AS TEXT), $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
			CASE WHEN cast($6 AS TEXT) IS NULL THEN NULL ELSE $1 END
		)
	`
	updatePortalQuery = `
		UPDATE portal
		SET mxid=$4, parent_id=$5, relay_login_id=cast($6 AS TEXT), relay_bridge_id=CASE WHEN cast($6 AS TEXT) IS NULL THEN NULL ELSE bridge_id END,
		    name=$7, topic=$8, avatar_id=$9, avatar_hash=$10, avatar_mxc=$11,
		    name_set=$12, avatar_set=$13, topic_set=$14, in_space=$15,
		    room_type=$16, disappear_type=$17, disappear_timer=$18, metadata=$19
		WHERE bridge_id=$1 AND id=$2 AND receiver=$3
	`
	deletePortalQuery = `
		DELETE FROM portal
		WHERE bridge_id=$1 AND id=$2 AND receiver=$3
	`
	reIDPortalQuery = `UPDATE portal SET id=$4, receiver=$5 WHERE bridge_id=$1 AND id=$2 AND receiver=$3`
)

func (pq *PortalQuery) GetByID(ctx context.Context, key networkid.PortalKey) (*Portal, error) {
	return pq.QueryOne(ctx, getPortalByIDQuery, pq.BridgeID, key.ID, key.Receiver)
}

func (pq *PortalQuery) FindReceiver(ctx context.Context, id networkid.PortalID, maybeReceiver networkid.UserLoginID) (key networkid.PortalKey, err error) {
	err = pq.GetDB().QueryRow(ctx, findPortalReceiverQuery, pq.BridgeID, id, maybeReceiver).Scan(&key.ID, &key.Receiver)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return
}

func (pq *PortalQuery) GetByIDWithUncertainReceiver(ctx context.Context, key networkid.PortalKey) (*Portal, error) {
	return pq.QueryOne(ctx, getPortalByIDWithUncertainReceiverQuery, pq.BridgeID, key.ID, key.Receiver)
}

func (pq *PortalQuery) GetByMXID(ctx context.Context, mxid id.RoomID) (*Portal, error) {
	return pq.QueryOne(ctx, getPortalByMXIDQuery, pq.BridgeID, mxid)
}

func (pq *PortalQuery) GetChildren(ctx context.Context, parentID networkid.PortalID) ([]*Portal, error) {
	return pq.QueryMany(ctx, getChildPortalsQuery, pq.BridgeID, parentID)
}

func (pq *PortalQuery) ReID(ctx context.Context, oldID, newID networkid.PortalKey) error {
	return pq.Exec(ctx, reIDPortalQuery, pq.BridgeID, oldID.ID, oldID.Receiver, newID.ID, newID.Receiver)
}

func (pq *PortalQuery) Insert(ctx context.Context, p *Portal) error {
	ensureBridgeIDMatches(&p.BridgeID, pq.BridgeID)
	return pq.Exec(ctx, insertPortalQuery, p.ensureHasMetadata(pq.MetaType).sqlVariables()...)
}

func (pq *PortalQuery) Update(ctx context.Context, p *Portal) error {
	ensureBridgeIDMatches(&p.BridgeID, pq.BridgeID)
	return pq.Exec(ctx, updatePortalQuery, p.ensureHasMetadata(pq.MetaType).sqlVariables()...)
}

func (pq *PortalQuery) Delete(ctx context.Context, key networkid.PortalKey) error {
	return pq.Exec(ctx, deletePortalQuery, pq.BridgeID, key.ID, key.Receiver)
}

func (p *Portal) Scan(row dbutil.Scannable) (*Portal, error) {
	var mxid, parentID, relayLoginID, disappearType sql.NullString
	var disappearTimer sql.NullInt64
	var avatarHash string
	err := row.Scan(
		&p.BridgeID, &p.ID, &p.Receiver, &mxid,
		&parentID, &relayLoginID, &p.Name, &p.Topic, &p.AvatarID, &avatarHash, &p.AvatarMXC,
		&p.NameSet, &p.TopicSet, &p.AvatarSet, &p.InSpace,
		&p.RoomType, &disappearType, &disappearTimer,
		dbutil.JSON{Data: p.Metadata},
	)
	if err != nil {
		return nil, err
	}
	if avatarHash != "" {
		data, _ := hex.DecodeString(avatarHash)
		if len(data) == 32 {
			p.AvatarHash = *(*[32]byte)(data)
		}
	}
	if disappearType.Valid {
		p.Disappear = DisappearingSetting{
			Type:  DisappearingType(disappearType.String),
			Timer: time.Duration(disappearTimer.Int64),
		}
	}
	p.MXID = id.RoomID(mxid.String)
	p.ParentID = networkid.PortalID(parentID.String)
	p.RelayLoginID = networkid.UserLoginID(relayLoginID.String)
	return p, nil
}

func (p *Portal) ensureHasMetadata(metaType MetaTypeCreator) *Portal {
	if p.Metadata == nil {
		p.Metadata = metaType()
	}
	return p
}

func (p *Portal) sqlVariables() []any {
	var avatarHash string
	if p.AvatarHash != [32]byte{} {
		avatarHash = hex.EncodeToString(p.AvatarHash[:])
	}
	return []any{
		p.BridgeID, p.ID, p.Receiver, dbutil.StrPtr(p.MXID),
		dbutil.StrPtr(p.ParentID), dbutil.StrPtr(p.RelayLoginID),
		p.Name, p.Topic, p.AvatarID, avatarHash, p.AvatarMXC,
		p.NameSet, p.TopicSet, p.AvatarSet, p.InSpace,
		dbutil.JSON{Data: p.Metadata},
	}
}
