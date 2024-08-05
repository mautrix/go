// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package database

import (
	"context"
	"encoding/hex"

	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/id"
)

type GhostQuery struct {
	BridgeID networkid.BridgeID
	MetaType MetaTypeCreator
	*dbutil.QueryHelper[*Ghost]
}

type Ghost struct {
	BridgeID networkid.BridgeID
	ID       networkid.UserID

	Name           string
	AvatarID       networkid.AvatarID
	AvatarHash     [32]byte
	AvatarMXC      id.ContentURIString
	NameSet        bool
	AvatarSet      bool
	ContactInfoSet bool
	IsBot          bool
	Identifiers    []string
	Metadata       any
}

const (
	getGhostBaseQuery = `
		SELECT bridge_id, id, name, avatar_id, avatar_hash, avatar_mxc,
		       name_set, avatar_set, contact_info_set, is_bot, identifiers, metadata
		FROM ghost
	`
	getGhostByIDQuery       = getGhostBaseQuery + `WHERE bridge_id=$1 AND id=$2`
	getGhostByMetadataQuery = getGhostBaseQuery + `WHERE bridge_id=$1 AND metadata->>$2=$3`
	insertGhostQuery        = `
		INSERT INTO ghost (
			bridge_id, id, name, avatar_id, avatar_hash, avatar_mxc,
			name_set, avatar_set, contact_info_set, is_bot, identifiers, metadata
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`
	updateGhostQuery = `
		UPDATE ghost SET name=$3, avatar_id=$4, avatar_hash=$5, avatar_mxc=$6,
		                 name_set=$7, avatar_set=$8, contact_info_set=$9, is_bot=$10, identifiers=$11, metadata=$12
		WHERE bridge_id=$1 AND id=$2
	`
)

func (gq *GhostQuery) GetByID(ctx context.Context, id networkid.UserID) (*Ghost, error) {
	return gq.QueryOne(ctx, getGhostByIDQuery, gq.BridgeID, id)
}

// GetByMetadata returns the ghosts whose metadata field at the given JSON key
// matches the given value.
func (gq *GhostQuery) GetByMetadata(ctx context.Context, key string, value any) ([]*Ghost, error) {
	return gq.QueryMany(ctx, getGhostByMetadataQuery, gq.BridgeID, key, value)
}

func (gq *GhostQuery) Insert(ctx context.Context, ghost *Ghost) error {
	ensureBridgeIDMatches(&ghost.BridgeID, gq.BridgeID)
	return gq.Exec(ctx, insertGhostQuery, ghost.ensureHasMetadata(gq.MetaType).sqlVariables()...)
}

func (gq *GhostQuery) Update(ctx context.Context, ghost *Ghost) error {
	ensureBridgeIDMatches(&ghost.BridgeID, gq.BridgeID)
	return gq.Exec(ctx, updateGhostQuery, ghost.ensureHasMetadata(gq.MetaType).sqlVariables()...)
}

func (g *Ghost) Scan(row dbutil.Scannable) (*Ghost, error) {
	var avatarHash string
	err := row.Scan(
		&g.BridgeID, &g.ID,
		&g.Name, &g.AvatarID, &avatarHash, &g.AvatarMXC,
		&g.NameSet, &g.AvatarSet, &g.ContactInfoSet, &g.IsBot,
		dbutil.JSON{Data: &g.Identifiers}, dbutil.JSON{Data: g.Metadata},
	)
	if err != nil {
		return nil, err
	}
	if avatarHash != "" {
		data, _ := hex.DecodeString(avatarHash)
		if len(data) == 32 {
			g.AvatarHash = *(*[32]byte)(data)
		}
	}
	return g, nil
}

func (g *Ghost) ensureHasMetadata(metaType MetaTypeCreator) *Ghost {
	if g.Metadata == nil {
		g.Metadata = metaType()
	}
	return g
}

func (g *Ghost) sqlVariables() []any {
	var avatarHash string
	if g.AvatarHash != [32]byte{} {
		avatarHash = hex.EncodeToString(g.AvatarHash[:])
	}
	return []any{
		g.BridgeID, g.ID,
		g.Name, g.AvatarID, avatarHash, g.AvatarMXC,
		g.NameSet, g.AvatarSet, g.ContactInfoSet, g.IsBot,
		dbutil.JSON{Data: &g.Identifiers}, dbutil.JSON{Data: g.Metadata},
	}
}
