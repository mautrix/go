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

type UserQuery struct {
	BridgeID networkid.BridgeID
	*dbutil.QueryHelper[*User]
}

type User struct {
	BridgeID networkid.BridgeID
	MXID     id.UserID

	ManagementRoom id.RoomID
	AccessToken    string
}

const (
	getUserBaseQuery = `
		SELECT bridge_id, mxid, management_room, access_token FROM "user"
	`
	getUserByMXIDQuery = getUserBaseQuery + `WHERE bridge_id=$1 AND mxid=$2`
	insertUserQuery    = `
		INSERT INTO "user" (bridge_id, mxid, management_room, access_token)
		VALUES ($1, $2, $3, $4)
	`
	updateUserQuery = `
		UPDATE "user" SET management_room=$3, access_token=$4
		WHERE bridge_id=$1 AND mxid=$2
	`
)

func (uq *UserQuery) GetByMXID(ctx context.Context, userID id.UserID) (*User, error) {
	return uq.QueryOne(ctx, getUserByMXIDQuery, uq.BridgeID, userID)
}

func (uq *UserQuery) Insert(ctx context.Context, user *User) error {
	ensureBridgeIDMatches(&user.BridgeID, uq.BridgeID)
	return uq.Exec(ctx, insertUserQuery, user.sqlVariables()...)
}

func (uq *UserQuery) Update(ctx context.Context, user *User) error {
	ensureBridgeIDMatches(&user.BridgeID, uq.BridgeID)
	return uq.Exec(ctx, updateUserQuery, user.sqlVariables()...)
}

func (u *User) Scan(row dbutil.Scannable) (*User, error) {
	var managementRoom, accessToken sql.NullString
	err := row.Scan(&u.BridgeID, &u.MXID, &managementRoom, &accessToken)
	if err != nil {
		return nil, err
	}
	u.ManagementRoom = id.RoomID(managementRoom.String)
	u.AccessToken = accessToken.String
	return u, nil
}

func (u *User) sqlVariables() []any {
	return []any{u.BridgeID, u.MXID, dbutil.StrPtr(u.ManagementRoom), dbutil.StrPtr(u.AccessToken)}
}
