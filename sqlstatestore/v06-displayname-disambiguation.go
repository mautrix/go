// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstatestore

import (
	"context"

	"go.mau.fi/util/confusable"
	"go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix/id"
)

type roomUserName struct {
	RoomID id.RoomID
	UserID id.UserID
	Name   string
}

func init() {
	UpgradeTable.Register(-1, 6, 3, "Add disambiguation column for user profiles", dbutil.TxnModeOn, func(ctx context.Context, db *dbutil.Database) error {
		_, err := db.Exec(ctx, `
			ALTER TABLE mx_user_profile ADD COLUMN name_skeleton bytea;
			CREATE INDEX mx_user_profile_membership_idx ON mx_user_profile (room_id, membership);
			CREATE INDEX mx_user_profile_name_skeleton_idx ON mx_user_profile (room_id, name_skeleton);
		`)
		if err != nil {
			return err
		}
		const ChunkSize = 1000
		const GetEntriesChunkQuery = "SELECT room_id, user_id, displayname FROM mx_user_profile WHERE displayname<>'' LIMIT $1 OFFSET $2"
		const SetSkeletonHashQuery = `UPDATE mx_user_profile SET name_skeleton = $3 WHERE room_id = $1 AND user_id = $2`
		for offset := 0; ; offset += ChunkSize {
			entries, err := dbutil.NewSimpleReflectRowIter[roomUserName](db.Query(ctx, GetEntriesChunkQuery, ChunkSize, offset)).AsList()
			if err != nil {
				return err
			}
			for _, entry := range entries {
				skel := confusable.SkeletonHash(entry.Name)
				_, err = db.Exec(ctx, SetSkeletonHashQuery, entry.RoomID, entry.UserID, skel[:])
				if err != nil {
					return err
				}
			}
			if len(entries) < ChunkSize {
				break
			}
		}
		return nil
	})
}
