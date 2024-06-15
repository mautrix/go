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
	*dbutil.QueryHelper[*Ghost]
}

type GhostMetadata struct {
	IsBot          bool     `json:"is_bot,omitempty"`
	Identifiers    []string `json:"identifiers,omitempty"`
	ContactInfoSet bool     `json:"contact_info_set,omitempty"`

	Extra map[string]any `json:"extra"`
}

type Ghost struct {
	BridgeID networkid.BridgeID
	ID       networkid.UserID

	Name       string
	AvatarID   networkid.AvatarID
	AvatarHash [32]byte
	AvatarMXC  id.ContentURIString
	NameSet    bool
	AvatarSet  bool
	Metadata   GhostMetadata
}

func newGhost(_ *dbutil.QueryHelper[*Ghost]) *Ghost {
	return &Ghost{}
}

const (
	getGhostBaseQuery = `
		SELECT bridge_id, id, name, avatar_id, avatar_hash, avatar_mxc, name_set, avatar_set, metadata FROM ghost
	`
	getGhostByIDQuery = getGhostBaseQuery + `WHERE bridge_id=$1 AND id=$2`
	insertGhostQuery  = `
		INSERT INTO ghost (bridge_id, id, name, avatar_id, avatar_hash, avatar_mxc, name_set, avatar_set, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	updateGhostQuery = `
		UPDATE ghost SET name=$3, avatar_id=$4, avatar_hash=$5, avatar_mxc=$6, name_set=$7, avatar_set=$8, metadata=$9
		WHERE bridge_id=$1 AND id=$2
	`
)

func (gq *GhostQuery) GetByID(ctx context.Context, id networkid.UserID) (*Ghost, error) {
	return gq.QueryOne(ctx, getGhostByIDQuery, gq.BridgeID, id)
}

func (gq *GhostQuery) Insert(ctx context.Context, ghost *Ghost) error {
	ensureBridgeIDMatches(&ghost.BridgeID, gq.BridgeID)
	return gq.Exec(ctx, insertGhostQuery, ghost.sqlVariables()...)
}

func (gq *GhostQuery) Update(ctx context.Context, ghost *Ghost) error {
	ensureBridgeIDMatches(&ghost.BridgeID, gq.BridgeID)
	return gq.Exec(ctx, updateGhostQuery, ghost.sqlVariables()...)
}

func (g *Ghost) Scan(row dbutil.Scannable) (*Ghost, error) {
	var avatarHash string
	err := row.Scan(
		&g.BridgeID, &g.ID,
		&g.Name, &g.AvatarID, &avatarHash, &g.AvatarMXC,
		&g.NameSet, &g.AvatarSet, dbutil.JSON{Data: &g.Metadata},
	)
	if err != nil {
		return nil, err
	}
	if g.Metadata.Extra == nil {
		g.Metadata.Extra = make(map[string]any)
	}
	if avatarHash != "" {
		data, _ := hex.DecodeString(avatarHash)
		if len(data) == 32 {
			g.AvatarHash = *(*[32]byte)(data)
		}
	}
	return g, nil
}

func (g *Ghost) sqlVariables() []any {
	if g.Metadata.Extra == nil {
		g.Metadata.Extra = make(map[string]any)
	}
	var avatarHash string
	if g.AvatarHash != [32]byte{} {
		avatarHash = hex.EncodeToString(g.AvatarHash[:])
	}
	return []any{
		g.BridgeID, g.ID,
		g.Name, g.AvatarID, avatarHash, g.AvatarMXC,
		g.NameSet, g.AvatarSet, dbutil.JSON{Data: &g.Metadata},
	}
}
