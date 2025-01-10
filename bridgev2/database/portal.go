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

type CapabilityState struct {
	Source networkid.UserLoginID `json:"source"`
	ID     string                `json:"id"`
}

type Portal struct {
	BridgeID networkid.BridgeID
	networkid.PortalKey
	MXID id.RoomID

	ParentKey    networkid.PortalKey
	RelayLoginID networkid.UserLoginID
	OtherUserID  networkid.UserID
	Name         string
	Topic        string
	AvatarID     networkid.AvatarID
	AvatarHash   [32]byte
	AvatarMXC    id.ContentURIString
	NameSet      bool
	TopicSet     bool
	AvatarSet    bool
	NameIsCustom bool
	InSpace      bool
	RoomType     RoomType
	Disappear    DisappearingSetting
	CapState     CapabilityState
	Metadata     any
}

const (
	getPortalBaseQuery = `
		SELECT bridge_id, id, receiver, mxid, parent_id, parent_receiver, relay_login_id, other_user_id,
		       name, topic, avatar_id, avatar_hash, avatar_mxc,
		       name_set, topic_set, avatar_set, name_is_custom, in_space,
		       room_type, disappear_type, disappear_timer, cap_state,
		       metadata
		FROM portal
	`
	getPortalByKeyQuery                     = getPortalBaseQuery + `WHERE bridge_id=$1 AND id=$2 AND receiver=$3`
	getPortalByIDWithUncertainReceiverQuery = getPortalBaseQuery + `WHERE bridge_id=$1 AND id=$2 AND (receiver=$3 OR receiver='')`
	getPortalByMXIDQuery                    = getPortalBaseQuery + `WHERE bridge_id=$1 AND mxid=$2`
	getAllPortalsWithMXIDQuery              = getPortalBaseQuery + `WHERE bridge_id=$1 AND mxid IS NOT NULL`
	getAllDMPortalsQuery                    = getPortalBaseQuery + `WHERE bridge_id=$1 AND room_type='dm' AND other_user_id=$2`
	getAllPortalsQuery                      = getPortalBaseQuery + `WHERE bridge_id=$1`
	getChildPortalsQuery                    = getPortalBaseQuery + `WHERE bridge_id=$1 AND parent_id=$2 AND parent_receiver=$3`

	findPortalReceiverQuery = `SELECT id, receiver FROM portal WHERE bridge_id=$1 AND id=$2 AND (receiver=$3 OR receiver='') LIMIT 1`

	insertPortalQuery = `
		INSERT INTO portal (
			bridge_id, id, receiver, mxid,
			parent_id, parent_receiver, relay_login_id, other_user_id,
			name, topic, avatar_id, avatar_hash, avatar_mxc,
			name_set, avatar_set, topic_set, name_is_custom, in_space,
			room_type, disappear_type, disappear_timer, cap_state,
			metadata, relay_bridge_id
		) VALUES (
			$1, $2, $3, $4, $5, $6, cast($7 AS TEXT), $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23,
			CASE WHEN cast($7 AS TEXT) IS NULL THEN NULL ELSE $1 END
		)
	`
	updatePortalQuery = `
		UPDATE portal
		SET mxid=$4, parent_id=$5, parent_receiver=$6,
		    relay_login_id=cast($7 AS TEXT), relay_bridge_id=CASE WHEN cast($7 AS TEXT) IS NULL THEN NULL ELSE bridge_id END,
		    other_user_id=$8, name=$9, topic=$10, avatar_id=$11, avatar_hash=$12, avatar_mxc=$13,
		    name_set=$14, avatar_set=$15, topic_set=$16, name_is_custom=$17, in_space=$18,
		    room_type=$19, disappear_type=$20, disappear_timer=$21, cap_state=$22, metadata=$23
		WHERE bridge_id=$1 AND id=$2 AND receiver=$3
	`
	deletePortalQuery = `
		DELETE FROM portal
		WHERE bridge_id=$1 AND id=$2 AND receiver=$3
	`
	reIDPortalQuery            = `UPDATE portal SET id=$4, receiver=$5 WHERE bridge_id=$1 AND id=$2 AND receiver=$3`
	migrateToSplitPortalsQuery = `
		UPDATE portal
		SET receiver=COALESCE((
			SELECT login_id
			FROM user_portal
			WHERE bridge_id=portal.bridge_id AND portal_id=portal.id AND portal_receiver=''
			LIMIT 1
		), (
			SELECT id FROM user_login WHERE bridge_id=portal.bridge_id LIMIT 1
		), '')
		WHERE receiver='' AND bridge_id=$1
	`
)

func (pq *PortalQuery) GetByKey(ctx context.Context, key networkid.PortalKey) (*Portal, error) {
	return pq.QueryOne(ctx, getPortalByKeyQuery, pq.BridgeID, key.ID, key.Receiver)
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

func (pq *PortalQuery) GetAllWithMXID(ctx context.Context) ([]*Portal, error) {
	return pq.QueryMany(ctx, getAllPortalsWithMXIDQuery, pq.BridgeID)
}

func (pq *PortalQuery) GetAll(ctx context.Context) ([]*Portal, error) {
	return pq.QueryMany(ctx, getAllPortalsQuery, pq.BridgeID)
}

func (pq *PortalQuery) GetAllDMsWith(ctx context.Context, otherUserID networkid.UserID) ([]*Portal, error) {
	return pq.QueryMany(ctx, getAllDMPortalsQuery, pq.BridgeID, otherUserID)
}

func (pq *PortalQuery) GetChildren(ctx context.Context, parentKey networkid.PortalKey) ([]*Portal, error) {
	return pq.QueryMany(ctx, getChildPortalsQuery, pq.BridgeID, parentKey.ID, parentKey.Receiver)
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

func (pq *PortalQuery) MigrateToSplitPortals(ctx context.Context) (int64, error) {
	res, err := pq.GetDB().Exec(ctx, migrateToSplitPortalsQuery, pq.BridgeID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (p *Portal) Scan(row dbutil.Scannable) (*Portal, error) {
	var mxid, parentID, parentReceiver, relayLoginID, otherUserID, disappearType sql.NullString
	var disappearTimer sql.NullInt64
	var avatarHash string
	err := row.Scan(
		&p.BridgeID, &p.ID, &p.Receiver, &mxid,
		&parentID, &parentReceiver, &relayLoginID, &otherUserID,
		&p.Name, &p.Topic, &p.AvatarID, &avatarHash, &p.AvatarMXC,
		&p.NameSet, &p.TopicSet, &p.AvatarSet, &p.NameIsCustom, &p.InSpace,
		&p.RoomType, &disappearType, &disappearTimer,
		dbutil.JSON{Data: &p.CapState}, dbutil.JSON{Data: p.Metadata},
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
	p.OtherUserID = networkid.UserID(otherUserID.String)
	if parentID.Valid {
		p.ParentKey = networkid.PortalKey{
			ID:       networkid.PortalID(parentID.String),
			Receiver: networkid.UserLoginID(parentReceiver.String),
		}
	}
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
		dbutil.StrPtr(p.ParentKey.ID), p.ParentKey.Receiver, dbutil.StrPtr(p.RelayLoginID), dbutil.StrPtr(p.OtherUserID),
		p.Name, p.Topic, p.AvatarID, avatarHash, p.AvatarMXC,
		p.NameSet, p.TopicSet, p.AvatarSet, p.NameIsCustom, p.InSpace,
		p.RoomType, dbutil.StrPtr(p.Disappear.Type), dbutil.NumPtr(p.Disappear.Timer),
		dbutil.JSON{Data: p.CapState}, dbutil.JSON{Data: p.Metadata},
	}
}
