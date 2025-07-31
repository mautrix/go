// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build cgo && !nocrypto

package matrix

import (
	"context"

	"github.com/lib/pq"
	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/id"
)

func init() {
	crypto.PostgresArrayWrapper = pq.Array
}

type SQLCryptoStore struct {
	*crypto.SQLCryptoStore
	UserID        id.UserID
	GhostIDFormat string
}

var _ crypto.Store = (*SQLCryptoStore)(nil)

func NewSQLCryptoStore(db *dbutil.Database, log dbutil.DatabaseLogger, accountID string, userID id.UserID, ghostIDFormat, pickleKey string) *SQLCryptoStore {
	return &SQLCryptoStore{
		SQLCryptoStore: crypto.NewSQLCryptoStore(db, log, accountID, "", []byte(pickleKey)),
		UserID:         userID,
		GhostIDFormat:  ghostIDFormat,
	}
}

func (store *SQLCryptoStore) GetRoomJoinedOrInvitedMembers(ctx context.Context, roomID id.RoomID) (members []id.UserID, err error) {
	var rows dbutil.Rows
	rows, err = store.DB.Query(ctx, `
		SELECT user_id FROM mx_user_profile
		WHERE room_id=$1
			AND (membership='join' OR membership='invite')
			AND user_id<>$2
			AND user_id NOT LIKE $3 ESCAPE '\'
	`, roomID, store.UserID, store.GhostIDFormat)
	if err != nil {
		return
	}
	for rows.Next() {
		var userID id.UserID
		err = rows.Scan(&userID)
		if err != nil {
			return members, err
		} else {
			members = append(members, userID)
		}
	}
	return
}
