// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package database

import (
	"context"
	"database/sql"

	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/id"
)

type UserLoginQuery struct {
	BridgeID networkid.BridgeID
	*dbutil.QueryHelper[*UserLogin]
}

type UserLogin struct {
	BridgeID  networkid.BridgeID
	UserMXID  id.UserID
	ID        networkid.UserLoginID
	SpaceRoom id.RoomID
	Metadata  map[string]any
}

func newUserLogin(_ *dbutil.QueryHelper[*UserLogin]) *UserLogin {
	return &UserLogin{}
}

const (
	getUserLoginBaseQuery = `
		SELECT bridge_id, user_mxid, id, space_room, metadata FROM user_login
	`
	getAllLoginsQuery        = getUserLoginBaseQuery + `WHERE bridge_id=$1`
	getAllLoginsForUserQuery = getUserLoginBaseQuery + `WHERE bridge_id=$1 AND user_mxid=$2`
	insertUserLoginQuery     = `
		INSERT INTO user_login (bridge_id, user_mxid, id, space_room, metadata)
		VALUES ($1, $2, $3, $4, $5)
	`
	updateUserLoginQuery = `
		UPDATE user_login SET space_room=$4, metadata=$5
		WHERE bridge_id=$1 AND user_mxid=$2 AND id=$3
	`
	insertUserPortalQuery = `
		INSERT INTO user_portal (bridge_id, user_mxid, login_id, portal_id, in_space, preferred)
		VALUES ($1, $2, $3, $4, false, false)
		ON CONFLICT (bridge_id, user_mxid, login_id, portal_id) DO NOTHING
	`
	upsertUserPortalQuery = `
		INSERT INTO user_portal (bridge_id, user_mxid, login_id, portal_id, in_space, preferred)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (bridge_id, user_mxid, login_id, portal_id) DO UPDATE SET in_space=excluded.in_space, preferred=excluded.preferred
	`
	markLoginAsPreferredQuery = `
		UPDATE user_portal SET preferred=(login_id=$3) WHERE bridge_id=$1 AND user_mxid=$2 AND portal_id=$4
	`
)

func (uq *UserLoginQuery) GetAll(ctx context.Context) ([]*UserLogin, error) {
	return uq.QueryMany(ctx, getAllLoginsQuery, uq.BridgeID)
}

func (uq *UserLoginQuery) GetAllForUser(ctx context.Context, userID id.UserID) ([]*UserLogin, error) {
	return uq.QueryMany(ctx, getAllLoginsForUserQuery, uq.BridgeID, userID)
}

func (uq *UserLoginQuery) Insert(ctx context.Context, login *UserLogin) error {
	ensureBridgeIDMatches(&login.BridgeID, uq.BridgeID)
	return uq.Exec(ctx, insertUserLoginQuery, login.sqlVariables()...)
}

func (uq *UserLoginQuery) Update(ctx context.Context, login *UserLogin) error {
	ensureBridgeIDMatches(&login.BridgeID, uq.BridgeID)
	return uq.Exec(ctx, updateUserLoginQuery, login.sqlVariables()...)
}

func (uq *UserLoginQuery) EnsureUserPortalExists(ctx context.Context, login *UserLogin, portalID networkid.PortalID) error {
	ensureBridgeIDMatches(&login.BridgeID, uq.BridgeID)
	return uq.Exec(ctx, insertUserPortalQuery, login.BridgeID, login.UserMXID, login.ID, portalID)
}

func (uq *UserLoginQuery) MarkLoginAsPreferredInPortal(ctx context.Context, login *UserLogin, portalID networkid.PortalID) error {
	ensureBridgeIDMatches(&login.BridgeID, uq.BridgeID)
	return uq.Exec(ctx, markLoginAsPreferredQuery, login.BridgeID, login.UserMXID, login.ID, portalID)
}

func (u *UserLogin) Scan(row dbutil.Scannable) (*UserLogin, error) {
	var spaceRoom sql.NullString
	err := row.Scan(&u.BridgeID, &u.UserMXID, &u.ID, &spaceRoom, dbutil.JSON{Data: &u.Metadata})
	if err != nil {
		return nil, err
	}
	if u.Metadata == nil {
		u.Metadata = make(map[string]any)
	}
	u.SpaceRoom = id.RoomID(spaceRoom.String)
	return u, nil
}

func (u *UserLogin) sqlVariables() []any {
	if u.Metadata == nil {
		u.Metadata = make(map[string]any)
	}
	return []any{u.BridgeID, u.UserMXID, u.ID, dbutil.StrPtr(u.SpaceRoom), dbutil.JSON{Data: u.Metadata}}
}
