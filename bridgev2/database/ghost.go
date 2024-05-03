// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package database

import (
	"context"

	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/id"
)

type GhostQuery struct {
	BridgeID networkid.BridgeID
	*dbutil.QueryHelper[*Ghost]
}

type Ghost struct {
	BridgeID networkid.BridgeID
	ID       networkid.UserID

	Name      string
	AvatarID  networkid.AvatarID
	AvatarMXC id.ContentURIString
	NameSet   bool
	AvatarSet bool
	Metadata  map[string]any
}

func newGhost(_ *dbutil.QueryHelper[*Ghost]) *Ghost {
	return &Ghost{}
}

const (
	getGhostBaseQuery = `
		SELECT bridge_id, id, name, avatar_id, avatar_mxc, name_set, avatar_set, metadata FROM ghost
	`
	getGhostByIDQuery = getGhostBaseQuery + `WHERE bridge_id=$1 AND id=$2`
	insertGhostQuery  = `
		INSERT INTO ghost (bridge_id, id, name, avatar_id, avatar_mxc, name_set, avatar_set, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	updateGhostQuery = `
		UPDATE ghost SET name=$3, avatar_id=$4, avatar_mxc=$5, name_set=$6, avatar_set=$7, metadata=$8
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
	err := row.Scan(
		&g.BridgeID, &g.ID,
		&g.Name, &g.AvatarID, &g.AvatarMXC,
		&g.NameSet, &g.AvatarSet, dbutil.JSON{Data: &g.Metadata},
	)
	if err != nil {
		return nil, err
	}
	if g.Metadata == nil {
		g.Metadata = make(map[string]any)
	}
	return g, nil
}

func (g *Ghost) sqlVariables() []any {
	if g.Metadata == nil {
		g.Metadata = make(map[string]any)
	}
	return []any{
		g.BridgeID, g.ID,
		g.Name, g.AvatarID, g.AvatarMXC,
		g.NameSet, g.AvatarSet, dbutil.JSON{Data: g.Metadata},
	}
}
