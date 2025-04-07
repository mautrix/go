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
	"maunium.net/go/mautrix/bridgev2/status"
	"maunium.net/go/mautrix/id"
)

type UserLoginQuery struct {
	BridgeID networkid.BridgeID
	MetaType MetaTypeCreator
	*dbutil.QueryHelper[*UserLogin]
}

type UserLogin struct {
	BridgeID      networkid.BridgeID
	UserMXID      id.UserID
	ID            networkid.UserLoginID
	RemoteName    string
	RemoteProfile status.RemoteProfile
	SpaceRoom     id.RoomID
	Metadata      any
}

const (
	getUserLoginBaseQuery = `
		SELECT bridge_id, user_mxid, id, remote_name, remote_profile, space_room, metadata FROM user_login
	`
	getLoginByIDQuery          = getUserLoginBaseQuery + `WHERE bridge_id=$1 AND id=$2`
	getAllUsersWithLoginsQuery = `SELECT DISTINCT user_mxid FROM user_login WHERE bridge_id=$1`
	getAllLoginsForUserQuery   = getUserLoginBaseQuery + `WHERE bridge_id=$1 AND user_mxid=$2`
	getAllLoginsInPortalQuery  = `
		SELECT ul.bridge_id, ul.user_mxid, ul.id, ul.remote_name, ul.remote_profile, ul.space_room, ul.metadata FROM user_portal
		LEFT JOIN user_login ul ON user_portal.bridge_id=ul.bridge_id AND user_portal.user_mxid=ul.user_mxid AND user_portal.login_id=ul.id
		WHERE user_portal.bridge_id=$1 AND user_portal.portal_id=$2 AND user_portal.portal_receiver=$3
	`
	insertUserLoginQuery = `
		INSERT INTO user_login (bridge_id, user_mxid, id, remote_name, remote_profile, space_room, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	updateUserLoginQuery = `
		UPDATE user_login SET remote_name=$4, remote_profile=$5, space_room=$6, metadata=$7
		WHERE bridge_id=$1 AND user_mxid=$2 AND id=$3
	`
	deleteUserLoginQuery = `
		DELETE FROM user_login WHERE bridge_id=$1 AND id=$2
	`
)

func (uq *UserLoginQuery) GetByID(ctx context.Context, id networkid.UserLoginID) (*UserLogin, error) {
	return uq.QueryOne(ctx, getLoginByIDQuery, uq.BridgeID, id)
}

func (uq *UserLoginQuery) GetAllUserIDsWithLogins(ctx context.Context) ([]id.UserID, error) {
	rows, err := uq.GetDB().Query(ctx, getAllUsersWithLoginsQuery, uq.BridgeID)
	return dbutil.NewRowIterWithError(rows, dbutil.ScanSingleColumn[id.UserID], err).AsList()
}

func (uq *UserLoginQuery) GetAllInPortal(ctx context.Context, portal networkid.PortalKey) ([]*UserLogin, error) {
	return uq.QueryMany(ctx, getAllLoginsInPortalQuery, uq.BridgeID, portal.ID, portal.Receiver)
}

func (uq *UserLoginQuery) GetAllForUser(ctx context.Context, userID id.UserID) ([]*UserLogin, error) {
	return uq.QueryMany(ctx, getAllLoginsForUserQuery, uq.BridgeID, userID)
}

func (uq *UserLoginQuery) Insert(ctx context.Context, login *UserLogin) error {
	ensureBridgeIDMatches(&login.BridgeID, uq.BridgeID)
	return uq.Exec(ctx, insertUserLoginQuery, login.ensureHasMetadata(uq.MetaType).sqlVariables()...)
}

func (uq *UserLoginQuery) Update(ctx context.Context, login *UserLogin) error {
	ensureBridgeIDMatches(&login.BridgeID, uq.BridgeID)
	return uq.Exec(ctx, updateUserLoginQuery, login.ensureHasMetadata(uq.MetaType).sqlVariables()...)
}

func (uq *UserLoginQuery) Delete(ctx context.Context, loginID networkid.UserLoginID) error {
	return uq.Exec(ctx, deleteUserLoginQuery, uq.BridgeID, loginID)
}

func (u *UserLogin) Scan(row dbutil.Scannable) (*UserLogin, error) {
	var spaceRoom sql.NullString
	err := row.Scan(
		&u.BridgeID,
		&u.UserMXID,
		&u.ID,
		&u.RemoteName,
		dbutil.JSON{Data: &u.RemoteProfile},
		&spaceRoom,
		dbutil.JSON{Data: u.Metadata},
	)
	if err != nil {
		return nil, err
	}
	u.SpaceRoom = id.RoomID(spaceRoom.String)
	return u, nil
}

func (u *UserLogin) ensureHasMetadata(metaType MetaTypeCreator) *UserLogin {
	if u.Metadata == nil {
		u.Metadata = metaType()
	}
	return u
}

func (u *UserLogin) sqlVariables() []any {
	var remoteProfile dbutil.JSON
	if !u.RemoteProfile.IsEmpty() {
		remoteProfile.Data = &u.RemoteProfile
	}
	return []any{u.BridgeID, u.UserMXID, u.ID, u.RemoteName, remoteProfile, dbutil.StrPtr(u.SpaceRoom), dbutil.JSON{Data: u.Metadata}}
}
