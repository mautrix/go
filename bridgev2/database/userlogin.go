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

type StandardUserLoginMetadata struct {
	RemoteName string `json:"remote_name,omitempty"`
}

type UserLoginMetadata struct {
	StandardUserLoginMetadata
	Extra map[string]any
}

func (ulm *UserLoginMetadata) UnmarshalJSON(data []byte) error {
	return unmarshalMerge(data, &ulm.StandardUserLoginMetadata, &ulm.Extra)
}

func (ulm *UserLoginMetadata) MarshalJSON() ([]byte, error) {
	return marshalMerge(&ulm.StandardUserLoginMetadata, ulm.Extra)
}

type UserLogin struct {
	BridgeID  networkid.BridgeID
	UserMXID  id.UserID
	ID        networkid.UserLoginID
	SpaceRoom id.RoomID
	Metadata  UserLoginMetadata
}

func newUserLogin(_ *dbutil.QueryHelper[*UserLogin]) *UserLogin {
	return &UserLogin{}
}

const (
	getUserLoginBaseQuery = `
		SELECT bridge_id, user_mxid, id, space_room, metadata FROM user_login
	`
	getLoginByIDQuery         = getUserLoginBaseQuery + `WHERE bridge_id=$1 AND id=$2`
	getAllLoginsQuery         = getUserLoginBaseQuery + `WHERE bridge_id=$1`
	getAllLoginsForUserQuery  = getUserLoginBaseQuery + `WHERE bridge_id=$1 AND user_mxid=$2`
	getAllLoginsInPortalQuery = `
		SELECT ul.bridge_id, ul.user_mxid, ul.id, ul.space_room, ul.metadata FROM user_portal
		LEFT JOIN user_login ul ON user_portal.bridge_id=ul.bridge_id AND user_portal.user_mxid=ul.user_mxid AND user_portal.login_id=ul.id
		WHERE user_portal.bridge_id=$1 AND user_portal.portal_id=$2 AND user_portal.portal_receiver=$3
	`
	insertUserLoginQuery = `
		INSERT INTO user_login (bridge_id, user_mxid, id, space_room, metadata)
		VALUES ($1, $2, $3, $4, $5)
	`
	updateUserLoginQuery = `
		UPDATE user_login SET space_room=$4, metadata=$5
		WHERE bridge_id=$1 AND user_mxid=$2 AND id=$3
	`
	deleteUserLoginQuery = `
		DELETE FROM user_login WHERE bridge_id=$1 AND id=$2
	`
)

func (uq *UserLoginQuery) GetByID(ctx context.Context, id networkid.UserLoginID) (*UserLogin, error) {
	return uq.QueryOne(ctx, getLoginByIDQuery, uq.BridgeID, id)
}

func (uq *UserLoginQuery) GetAll(ctx context.Context) ([]*UserLogin, error) {
	return uq.QueryMany(ctx, getAllLoginsQuery, uq.BridgeID)
}

func (uq *UserLoginQuery) GetAllInPortal(ctx context.Context, portal networkid.PortalKey) ([]*UserLogin, error) {
	return uq.QueryMany(ctx, getAllLoginsInPortalQuery, uq.BridgeID, portal.ID, portal.Receiver)
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

func (uq *UserLoginQuery) Delete(ctx context.Context, loginID networkid.UserLoginID) error {
	return uq.Exec(ctx, deleteUserLoginQuery, uq.BridgeID, loginID)
}

func (u *UserLogin) Scan(row dbutil.Scannable) (*UserLogin, error) {
	var spaceRoom sql.NullString
	err := row.Scan(&u.BridgeID, &u.UserMXID, &u.ID, &spaceRoom, dbutil.JSON{Data: &u.Metadata})
	if err != nil {
		return nil, err
	}
	if u.Metadata.Extra == nil {
		u.Metadata.Extra = make(map[string]any)
	}
	u.SpaceRoom = id.RoomID(spaceRoom.String)
	return u, nil
}

func (u *UserLogin) sqlVariables() []any {
	if u.Metadata.Extra == nil {
		u.Metadata.Extra = make(map[string]any)
	}
	return []any{u.BridgeID, u.UserMXID, u.ID, dbutil.StrPtr(u.SpaceRoom), dbutil.JSON{Data: &u.Metadata}}
}
