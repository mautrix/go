// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/id"
)

type Ghost struct {
	*database.Ghost
	Bridge *Bridge
	Log    zerolog.Logger
	Intent MatrixAPI
	MXID   id.UserID
}

func (br *Bridge) loadGhost(ctx context.Context, dbGhost *database.Ghost, queryErr error, id *networkid.UserID) (*Ghost, error) {
	if queryErr != nil {
		return nil, fmt.Errorf("failed to query db: %w", queryErr)
	}
	if dbGhost == nil {
		if id == nil {
			return nil, nil
		}
		dbGhost = &database.Ghost{
			BridgeID: br.ID,
			ID:       *id,
		}
		err := br.DB.Ghost.Insert(ctx, dbGhost)
		if err != nil {
			return nil, fmt.Errorf("failed to insert new ghost: %w", err)
		}
	}
	mxid := br.Matrix.FormatGhostMXID(dbGhost.ID)
	ghost := &Ghost{
		Ghost:  dbGhost,
		Bridge: br,
		Log:    br.Log.With().Str("ghost_id", string(dbGhost.ID)).Logger(),
		Intent: br.Matrix.GhostIntent(mxid),
		MXID:   mxid,
	}
	br.ghostsByID[ghost.ID] = ghost
	return ghost, nil
}

func (br *Bridge) unlockedGetGhostByID(ctx context.Context, id networkid.UserID, onlyIfExists bool) (*Ghost, error) {
	cached, ok := br.ghostsByID[id]
	if ok {
		return cached, nil
	}
	idPtr := &id
	if onlyIfExists {
		idPtr = nil
	}
	db, err := br.DB.Ghost.GetByID(ctx, id)
	return br.loadGhost(ctx, db, err, idPtr)
}

func (br *Bridge) GetGhostByMXID(ctx context.Context, mxid id.UserID) (*Ghost, error) {
	ghostID, ok := br.Matrix.ParseGhostMXID(mxid)
	if !ok {
		return nil, nil
	}
	return br.GetGhostByID(ctx, ghostID)
}

func (br *Bridge) GetGhostByID(ctx context.Context, id networkid.UserID) (*Ghost, error) {
	br.cacheLock.Lock()
	defer br.cacheLock.Unlock()
	return br.unlockedGetGhostByID(ctx, id, false)
}

func (ghost *Ghost) IntentFor(portal *Portal) MatrixAPI {
	// TODO use user double puppet intent if appropriate
	return ghost.Intent
}
