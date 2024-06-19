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
	"time"

	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/id"
)

type PortalQuery struct {
	BridgeID networkid.BridgeID
	*dbutil.QueryHelper[*Portal]
}

type StandardPortalMetadata struct {
	DisappearType  DisappearingType `json:"disappear_type,omitempty"`
	DisappearTimer time.Duration    `json:"disappear_timer,omitempty"`
}

type PortalMetadata struct {
	StandardPortalMetadata
	Extra map[string]any
}

func (pm *PortalMetadata) UnmarshalJSON(data []byte) error {
	return unmarshalMerge(data, &pm.StandardPortalMetadata, &pm.Extra)
}

func (pm *PortalMetadata) MarshalJSON() ([]byte, error) {
	return marshalMerge(&pm.StandardPortalMetadata, pm.Extra)
}

type Portal struct {
	BridgeID networkid.BridgeID
	networkid.PortalKey
	MXID id.RoomID

	ParentID   networkid.PortalID
	Name       string
	Topic      string
	AvatarID   networkid.AvatarID
	AvatarHash [32]byte
	AvatarMXC  id.ContentURIString
	NameSet    bool
	TopicSet   bool
	AvatarSet  bool
	InSpace    bool
	Metadata   PortalMetadata
}

func newPortal(_ *dbutil.QueryHelper[*Portal]) *Portal {
	return &Portal{}
}

const (
	getPortalBaseQuery = `
		SELECT bridge_id, id, receiver, mxid, parent_id, name, topic, avatar_id, avatar_hash, avatar_mxc,
		       name_set, topic_set, avatar_set, in_space,
		       metadata
		FROM portal
	`
	getPortalByIDQuery                      = getPortalBaseQuery + `WHERE bridge_id=$1 AND id=$2 AND receiver=$3`
	getPortalByIDWithUncertainReceiverQuery = getPortalBaseQuery + `WHERE bridge_id=$1 AND id=$2 AND (receiver=$3 OR receiver='')`
	getPortalByMXIDQuery                    = getPortalBaseQuery + `WHERE bridge_id=$1 AND mxid=$2`
	getChildPortalsQuery                    = getPortalBaseQuery + `WHERE bridge_id=$1 AND parent_id=$2`

	insertPortalQuery = `
		INSERT INTO portal (
			bridge_id, id, receiver, mxid,
			parent_id, name, topic, avatar_id, avatar_hash, avatar_mxc,
			name_set, avatar_set, topic_set, in_space,
			metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`
	updatePortalQuery = `
		UPDATE portal
		SET mxid=$4, parent_id=$5, name=$6, topic=$7, avatar_id=$8, avatar_hash=$9, avatar_mxc=$10,
		    name_set=$11, avatar_set=$12, topic_set=$13, in_space=$14, metadata=$15
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
	return pq.Exec(ctx, insertPortalQuery, p.sqlVariables()...)
}

func (pq *PortalQuery) Update(ctx context.Context, p *Portal) error {
	ensureBridgeIDMatches(&p.BridgeID, pq.BridgeID)
	return pq.Exec(ctx, updatePortalQuery, p.sqlVariables()...)
}

func (pq *PortalQuery) Delete(ctx context.Context, key networkid.PortalKey) error {
	return pq.Exec(ctx, deletePortalQuery, pq.BridgeID, key.ID, key.Receiver)
}

func (p *Portal) Scan(row dbutil.Scannable) (*Portal, error) {
	var mxid, parentID sql.NullString
	var avatarHash string
	err := row.Scan(
		&p.BridgeID, &p.ID, &p.Receiver, &mxid,
		&parentID, &p.Name, &p.Topic, &p.AvatarID, &avatarHash, &p.AvatarMXC,
		&p.NameSet, &p.TopicSet, &p.AvatarSet, &p.InSpace,
		dbutil.JSON{Data: &p.Metadata},
	)
	if err != nil {
		return nil, err
	}
	if p.Metadata.Extra == nil {
		p.Metadata.Extra = make(map[string]any)
	}
	if avatarHash != "" {
		data, _ := hex.DecodeString(avatarHash)
		if len(data) == 32 {
			p.AvatarHash = *(*[32]byte)(data)
		}
	}
	p.MXID = id.RoomID(mxid.String)
	p.ParentID = networkid.PortalID(parentID.String)
	return p, nil
}

func (p *Portal) sqlVariables() []any {
	if p.Metadata.Extra == nil {
		p.Metadata.Extra = make(map[string]any)
	}
	var avatarHash string
	if p.AvatarHash != [32]byte{} {
		avatarHash = hex.EncodeToString(p.AvatarHash[:])
	}
	return []any{
		p.BridgeID, p.ID, p.Receiver, dbutil.StrPtr(p.MXID),
		dbutil.StrPtr(p.ParentID), p.Name, p.Topic, p.AvatarID, avatarHash, p.AvatarMXC,
		p.NameSet, p.TopicSet, p.AvatarSet, p.InSpace,
		dbutil.JSON{Data: p.Metadata},
	}
}
