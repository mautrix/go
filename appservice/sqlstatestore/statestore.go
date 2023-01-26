// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstatestore

import (
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"sync"

	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/util/dbutil"
)

//go:embed *.sql
var rawUpgrades embed.FS

var UpgradeTable dbutil.UpgradeTable

func init() {
	UpgradeTable.RegisterFS(rawUpgrades)
}

const VersionTableName = "mx_version"

type SQLStateStore struct {
	*dbutil.Database

	Typing     map[id.RoomID]map[id.UserID]int64
	typingLock sync.RWMutex
}

var _ appservice.StateStore = (*SQLStateStore)(nil)

func NewSQLStateStore(db *dbutil.Database, log dbutil.DatabaseLogger) *SQLStateStore {
	return &SQLStateStore{
		Database: db.Child(VersionTableName, UpgradeTable, log),
	}
}

func (store *SQLStateStore) IsRegistered(userID id.UserID) bool {
	var isRegistered bool
	err := store.
		QueryRow("SELECT EXISTS(SELECT 1 FROM mx_registrations WHERE user_id=$1)", userID).
		Scan(&isRegistered)
	if err != nil {
		store.Log.Warn("Failed to scan registration existence for %s: %v", userID, err)
	}
	return isRegistered
}

func (store *SQLStateStore) MarkRegistered(userID id.UserID) {
	_, err := store.Exec("INSERT INTO mx_registrations (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING", userID)
	if err != nil {
		store.Log.Warn("Failed to mark %s as registered: %v", userID, err)
	}
}

func (store *SQLStateStore) GetRoomMembers(roomID id.RoomID) map[id.UserID]*event.MemberEventContent {
	members := make(map[id.UserID]*event.MemberEventContent)
	rows, err := store.Query("SELECT user_id, membership, displayname, avatar_url FROM mx_user_profile WHERE room_id=$1", roomID)
	if err != nil {
		return members
	}
	var userID id.UserID
	var member event.MemberEventContent
	for rows.Next() {
		err = rows.Scan(&userID, &member.Membership, &member.Displayname, &member.AvatarURL)
		if err != nil {
			store.Log.Warn("Failed to scan member in %s: %v", roomID, err)
		} else {
			members[userID] = &member
		}
	}
	return members
}

func (store *SQLStateStore) GetMembership(roomID id.RoomID, userID id.UserID) event.Membership {
	membership := event.MembershipLeave
	err := store.
		QueryRow("SELECT membership FROM mx_user_profile WHERE room_id=$1 AND user_id=$2", roomID, userID).
		Scan(&membership)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		store.Log.Warn("Failed to scan membership of %s in %s: %v", userID, roomID, err)
	}
	return membership
}

func (store *SQLStateStore) GetMember(roomID id.RoomID, userID id.UserID) *event.MemberEventContent {
	member, ok := store.TryGetMember(roomID, userID)
	if !ok {
		member.Membership = event.MembershipLeave
	}
	return member
}

func (store *SQLStateStore) TryGetMember(roomID id.RoomID, userID id.UserID) (*event.MemberEventContent, bool) {
	var member event.MemberEventContent
	err := store.
		QueryRow("SELECT membership, displayname, avatar_url FROM mx_user_profile WHERE room_id=$1 AND user_id=$2", roomID, userID).
		Scan(&member.Membership, &member.Displayname, &member.AvatarURL)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		store.Log.Warn("Failed to scan member info of %s in %s: %v", userID, roomID, err)
	}
	return &member, err == nil
}

func (store *SQLStateStore) FindSharedRooms(userID id.UserID) (rooms []id.RoomID) {
	rows, err := store.Query(`
		SELECT room_id FROM mx_user_profile
		LEFT JOIN portal ON portal.mxid=mx_user_profile.room_id
		WHERE mx_user_profile.user_id=$1 AND portal.encrypted=true
	`, userID)
	if err != nil {
		store.Log.Warn("Failed to query shared rooms with %s: %v", userID, err)
		return
	}
	for rows.Next() {
		var roomID id.RoomID
		err = rows.Scan(&roomID)
		if err != nil {
			store.Log.Warn("Failed to scan room ID: %v", err)
		} else {
			rooms = append(rooms, roomID)
		}
	}
	return
}

func (store *SQLStateStore) IsInRoom(roomID id.RoomID, userID id.UserID) bool {
	return store.IsMembership(roomID, userID, "join")
}

func (store *SQLStateStore) IsInvited(roomID id.RoomID, userID id.UserID) bool {
	return store.IsMembership(roomID, userID, "join", "invite")
}

func (store *SQLStateStore) IsMembership(roomID id.RoomID, userID id.UserID, allowedMemberships ...event.Membership) bool {
	membership := store.GetMembership(roomID, userID)
	for _, allowedMembership := range allowedMemberships {
		if allowedMembership == membership {
			return true
		}
	}
	return false
}

func (store *SQLStateStore) SetMembership(roomID id.RoomID, userID id.UserID, membership event.Membership) {
	_, err := store.Exec(`
		INSERT INTO mx_user_profile (room_id, user_id, membership, displayname, avatar_url) VALUES ($1, $2, $3, '', '')
		ON CONFLICT (room_id, user_id) DO UPDATE SET membership=excluded.membership
	`, roomID, userID, membership)
	if err != nil {
		store.Log.Warn("Failed to set membership of %s in %s to %s: %v", userID, roomID, membership, err)
	}
}

func (store *SQLStateStore) SetMember(roomID id.RoomID, userID id.UserID, member *event.MemberEventContent) {
	_, err := store.Exec(`
		INSERT INTO mx_user_profile (room_id, user_id, membership, displayname, avatar_url) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (room_id, user_id) DO UPDATE SET membership=excluded.membership, displayname=excluded.displayname, avatar_url=excluded.avatar_url
	`, roomID, userID, member.Membership, member.Displayname, member.AvatarURL)
	if err != nil {
		store.Log.Warn("Failed to set membership of %s in %s to %s: %v", userID, roomID, member, err)
	}
}

func (store *SQLStateStore) SetPowerLevels(roomID id.RoomID, levels *event.PowerLevelsEventContent) {
	levelsBytes, err := json.Marshal(levels)
	if err != nil {
		store.Log.Warn("Failed to marshal power levels of %s: %v", roomID, err)
		return
	}
	_, err = store.Exec(`
		INSERT INTO mx_room_state (room_id, power_levels) VALUES ($1, $2)
		ON CONFLICT (room_id) DO UPDATE SET power_levels=excluded.power_levels
	`, roomID, levelsBytes)
	if err != nil {
		store.Log.Warn("Failed to store power levels of %s: %v", roomID, err)
	}
}

func (store *SQLStateStore) GetPowerLevels(roomID id.RoomID) (levels *event.PowerLevelsEventContent) {
	var data []byte
	err := store.
		QueryRow("SELECT power_levels FROM mx_room_state WHERE room_id=$1", roomID).
		Scan(&data)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			store.Log.Warn("Failed to scan power levels of %s: %v", roomID, err)
		}
		return
	}
	levels = &event.PowerLevelsEventContent{}
	err = json.Unmarshal(data, levels)
	if err != nil {
		store.Log.Warn("Failed to parse power levels of %s: %v", roomID, err)
		return nil
	}
	return
}

func (store *SQLStateStore) GetPowerLevel(roomID id.RoomID, userID id.UserID) int {
	if store.Dialect == dbutil.Postgres {
		var powerLevel int
		err := store.
			QueryRow(`
				SELECT COALESCE((power_levels->'users'->$2)::int, (power_levels->'users_default')::int, 0)
				FROM mx_room_state WHERE room_id=$1
			`, roomID, userID).
			Scan(&powerLevel)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			store.Log.Warn("Failed to scan power level of %s in %s: %v", userID, roomID, err)
		}
		return powerLevel
	}
	return store.GetPowerLevels(roomID).GetUserLevel(userID)
}

func (store *SQLStateStore) GetPowerLevelRequirement(roomID id.RoomID, eventType event.Type) int {
	if store.Dialect == dbutil.Postgres {
		defaultType := "events_default"
		defaultValue := 0
		if eventType.IsState() {
			defaultType = "state_default"
			defaultValue = 50
		}
		var powerLevel int
		err := store.
			QueryRow(`
				SELECT COALESCE((power_levels->'events'->$2)::int, (power_levels->'$3')::int, $4)
				FROM mx_room_state WHERE room_id=$1
			`, roomID, eventType.Type, defaultType, defaultValue).
			Scan(&powerLevel)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				store.Log.Warn("Failed to scan power level for %s in %s: %v", eventType, roomID, err)
			}
			return defaultValue
		}
		return powerLevel
	}
	return store.GetPowerLevels(roomID).GetEventLevel(eventType)
}

func (store *SQLStateStore) HasPowerLevel(roomID id.RoomID, userID id.UserID, eventType event.Type) bool {
	if store.Dialect == dbutil.Postgres {
		defaultType := "events_default"
		defaultValue := 0
		if eventType.IsState() {
			defaultType = "state_default"
			defaultValue = 50
		}
		var hasPower bool
		err := store.
			QueryRow(`SELECT
				COALESCE((power_levels->'users'->$2)::int, (power_levels->'users_default')::int, 0)
				>=
				COALESCE((power_levels->'events'->$3)::int, (power_levels->'$4')::int, $5)
				FROM mx_room_state WHERE room_id=$1`, roomID, userID, eventType.Type, defaultType, defaultValue).
			Scan(&hasPower)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				store.Log.Warn("Failed to scan power level for %s in %s: %v", eventType, roomID, err)
			}
			return defaultValue == 0
		}
		return hasPower
	}
	return store.GetPowerLevel(roomID, userID) >= store.GetPowerLevelRequirement(roomID, eventType)
}
