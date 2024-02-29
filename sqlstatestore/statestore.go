// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstatestore

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"

	"github.com/element-hq/mautrix-go/event"
	"github.com/element-hq/mautrix-go/id"
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
	IsBridge bool
}

func NewSQLStateStore(db *dbutil.Database, log dbutil.DatabaseLogger, isBridge bool) *SQLStateStore {
	return &SQLStateStore{
		Database: db.Child(VersionTableName, UpgradeTable, log),
		IsBridge: isBridge,
	}
}

func (store *SQLStateStore) IsRegistered(ctx context.Context, userID id.UserID) (bool, error) {
	var isRegistered bool
	err := store.
		QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM mx_registrations WHERE user_id=$1)", userID).
		Scan(&isRegistered)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return isRegistered, err
}

func (store *SQLStateStore) MarkRegistered(ctx context.Context, userID id.UserID) error {
	_, err := store.Exec(ctx, "INSERT INTO mx_registrations (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING", userID)
	return err
}

type Member struct {
	id.UserID
	event.MemberEventContent
}

func (store *SQLStateStore) GetRoomMembers(ctx context.Context, roomID id.RoomID, memberships ...event.Membership) (map[id.UserID]*event.MemberEventContent, error) {
	args := make([]any, len(memberships)+1)
	args[0] = roomID
	query := "SELECT user_id, membership, displayname, avatar_url FROM mx_user_profile WHERE room_id=$1"
	if len(memberships) > 0 {
		placeholders := make([]string, len(memberships))
		for i, membership := range memberships {
			args[i+1] = string(membership)
			placeholders[i] = fmt.Sprintf("$%d", i+2)
		}
		query = fmt.Sprintf("%s AND membership IN (%s)", query, strings.Join(placeholders, ","))
	}
	rows, err := store.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	members := make(map[id.UserID]*event.MemberEventContent)
	return members, dbutil.NewRowIter(rows, func(row dbutil.Scannable) (ret Member, err error) {
		err = row.Scan(&ret.UserID, &ret.Membership, &ret.Displayname, &ret.AvatarURL)
		return
	}).Iter(func(m Member) (bool, error) {
		members[m.UserID] = &m.MemberEventContent
		return true, nil
	})
}

func (store *SQLStateStore) GetRoomJoinedOrInvitedMembers(ctx context.Context, roomID id.RoomID) (members []id.UserID, err error) {
	var memberMap map[id.UserID]*event.MemberEventContent
	memberMap, err = store.GetRoomMembers(ctx, roomID, event.MembershipJoin, event.MembershipInvite)
	if err != nil {
		return
	}
	members = make([]id.UserID, len(memberMap))
	i := 0
	for userID := range memberMap {
		members[i] = userID
		i++
	}
	return
}

func (store *SQLStateStore) GetMembership(ctx context.Context, roomID id.RoomID, userID id.UserID) (membership event.Membership, err error) {
	err = store.
		QueryRow(ctx, "SELECT membership FROM mx_user_profile WHERE room_id=$1 AND user_id=$2", roomID, userID).
		Scan(&membership)
	if errors.Is(err, sql.ErrNoRows) {
		membership = event.MembershipLeave
		err = nil
	}
	return
}

func (store *SQLStateStore) GetMember(ctx context.Context, roomID id.RoomID, userID id.UserID) (*event.MemberEventContent, error) {
	member, err := store.TryGetMember(ctx, roomID, userID)
	if member == nil && err == nil {
		member = &event.MemberEventContent{Membership: event.MembershipLeave}
	}
	return member, err
}

func (store *SQLStateStore) TryGetMember(ctx context.Context, roomID id.RoomID, userID id.UserID) (*event.MemberEventContent, error) {
	var member event.MemberEventContent
	err := store.
		QueryRow(ctx, "SELECT membership, displayname, avatar_url FROM mx_user_profile WHERE room_id=$1 AND user_id=$2", roomID, userID).
		Scan(&member.Membership, &member.Displayname, &member.AvatarURL)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &member, nil
}

func (store *SQLStateStore) FindSharedRooms(ctx context.Context, userID id.UserID) ([]id.RoomID, error) {
	query := `
		SELECT room_id FROM mx_user_profile
		LEFT JOIN portal ON portal.mxid=mx_user_profile.room_id
		WHERE mx_user_profile.user_id=$1 AND portal.encrypted=true
	`
	if !store.IsBridge {
		query = `
			SELECT mx_user_profile.room_id FROM mx_user_profile
			LEFT JOIN mx_room_state ON mx_room_state.room_id=mx_user_profile.room_id
			WHERE mx_user_profile.user_id=$1 AND mx_room_state.encryption IS NOT NULL
		`
	}
	rows, err := store.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	return dbutil.NewRowIter(rows, dbutil.ScanSingleColumn[id.RoomID]).AsList()
}

func (store *SQLStateStore) IsInRoom(ctx context.Context, roomID id.RoomID, userID id.UserID) bool {
	return store.IsMembership(ctx, roomID, userID, "join")
}

func (store *SQLStateStore) IsInvited(ctx context.Context, roomID id.RoomID, userID id.UserID) bool {
	return store.IsMembership(ctx, roomID, userID, "join", "invite")
}

func (store *SQLStateStore) IsMembership(ctx context.Context, roomID id.RoomID, userID id.UserID, allowedMemberships ...event.Membership) bool {
	membership, err := store.GetMembership(ctx, roomID, userID)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to get membership")
		return false
	}
	for _, allowedMembership := range allowedMemberships {
		if allowedMembership == membership {
			return true
		}
	}
	return false
}

func (store *SQLStateStore) SetMembership(ctx context.Context, roomID id.RoomID, userID id.UserID, membership event.Membership) error {
	_, err := store.Exec(ctx, `
		INSERT INTO mx_user_profile (room_id, user_id, membership, displayname, avatar_url) VALUES ($1, $2, $3, '', '')
		ON CONFLICT (room_id, user_id) DO UPDATE SET membership=excluded.membership
	`, roomID, userID, membership)
	return err
}

func (store *SQLStateStore) SetMember(ctx context.Context, roomID id.RoomID, userID id.UserID, member *event.MemberEventContent) error {
	_, err := store.Exec(ctx, `
		INSERT INTO mx_user_profile (room_id, user_id, membership, displayname, avatar_url) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (room_id, user_id) DO UPDATE SET membership=excluded.membership, displayname=excluded.displayname, avatar_url=excluded.avatar_url
	`, roomID, userID, member.Membership, member.Displayname, member.AvatarURL)
	return err
}

func (store *SQLStateStore) ClearCachedMembers(ctx context.Context, roomID id.RoomID, memberships ...event.Membership) error {
	query := "DELETE FROM mx_user_profile WHERE room_id=$1"
	params := make([]any, len(memberships)+1)
	params[0] = roomID
	if len(memberships) > 0 {
		placeholders := make([]string, len(memberships))
		for i, membership := range memberships {
			placeholders[i] = "$" + strconv.Itoa(i+2)
			params[i+1] = string(membership)
		}
		query += fmt.Sprintf(" AND membership IN (%s)", strings.Join(placeholders, ","))
	}
	_, err := store.Exec(ctx, query, params...)
	return err
}

func (store *SQLStateStore) SetEncryptionEvent(ctx context.Context, roomID id.RoomID, content *event.EncryptionEventContent) error {
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return fmt.Errorf("failed to marshal content JSON: %w", err)
	}
	_, err = store.Exec(ctx, `
		INSERT INTO mx_room_state (room_id, encryption) VALUES ($1, $2)
		ON CONFLICT (room_id) DO UPDATE SET encryption=excluded.encryption
	`, roomID, contentBytes)
	return err
}

func (store *SQLStateStore) GetEncryptionEvent(ctx context.Context, roomID id.RoomID) (*event.EncryptionEventContent, error) {
	var data []byte
	err := store.
		QueryRow(ctx, "SELECT encryption FROM mx_room_state WHERE room_id=$1", roomID).
		Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	} else if data == nil {
		return nil, nil
	}
	var content event.EncryptionEventContent
	err = json.Unmarshal(data, &content)
	if err != nil {
		return nil, fmt.Errorf("failed to parse content JSON: %w", err)
	}
	return &content, nil
}

func (store *SQLStateStore) IsEncrypted(ctx context.Context, roomID id.RoomID) (bool, error) {
	cfg, err := store.GetEncryptionEvent(ctx, roomID)
	return cfg != nil && cfg.Algorithm == id.AlgorithmMegolmV1, err
}

func (store *SQLStateStore) SetPowerLevels(ctx context.Context, roomID id.RoomID, levels *event.PowerLevelsEventContent) error {
	_, err := store.Exec(ctx, `
		INSERT INTO mx_room_state (room_id, power_levels) VALUES ($1, $2)
		ON CONFLICT (room_id) DO UPDATE SET power_levels=excluded.power_levels
	`, roomID, dbutil.JSON{Data: levels})
	return err
}

func (store *SQLStateStore) GetPowerLevels(ctx context.Context, roomID id.RoomID) (levels *event.PowerLevelsEventContent, err error) {
	err = store.
		QueryRow(ctx, "SELECT power_levels FROM mx_room_state WHERE room_id=$1", roomID).
		Scan(&dbutil.JSON{Data: &levels})
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return
}

func (store *SQLStateStore) GetPowerLevel(ctx context.Context, roomID id.RoomID, userID id.UserID) (int, error) {
	if store.Dialect == dbutil.Postgres {
		var powerLevel int
		err := store.
			QueryRow(ctx, `
				SELECT COALESCE((power_levels->'users'->$2)::int, (power_levels->'users_default')::int, 0)
				FROM mx_room_state WHERE room_id=$1
			`, roomID, userID).
			Scan(&powerLevel)
		return powerLevel, err
	} else {
		levels, err := store.GetPowerLevels(ctx, roomID)
		if err != nil {
			return 0, err
		}
		return levels.GetUserLevel(userID), nil
	}
}

func (store *SQLStateStore) GetPowerLevelRequirement(ctx context.Context, roomID id.RoomID, eventType event.Type) (int, error) {
	if store.Dialect == dbutil.Postgres {
		defaultType := "events_default"
		defaultValue := 0
		if eventType.IsState() {
			defaultType = "state_default"
			defaultValue = 50
		}
		var powerLevel int
		err := store.
			QueryRow(ctx, `
				SELECT COALESCE((power_levels->'events'->$2)::int, (power_levels->'$3')::int, $4)
				FROM mx_room_state WHERE room_id=$1
			`, roomID, eventType.Type, defaultType, defaultValue).
			Scan(&powerLevel)
		if errors.Is(err, sql.ErrNoRows) {
			err = nil
			powerLevel = defaultValue
		}
		return powerLevel, err
	} else {
		levels, err := store.GetPowerLevels(ctx, roomID)
		if err != nil {
			return 0, err
		}
		return levels.GetEventLevel(eventType), nil
	}
}

func (store *SQLStateStore) HasPowerLevel(ctx context.Context, roomID id.RoomID, userID id.UserID, eventType event.Type) (bool, error) {
	if store.Dialect == dbutil.Postgres {
		defaultType := "events_default"
		defaultValue := 0
		if eventType.IsState() {
			defaultType = "state_default"
			defaultValue = 50
		}
		var hasPower bool
		err := store.
			QueryRow(ctx, `SELECT
				COALESCE((power_levels->'users'->$2)::int, (power_levels->'users_default')::int, 0)
				>=
				COALESCE((power_levels->'events'->$3)::int, (power_levels->'$4')::int, $5)
				FROM mx_room_state WHERE room_id=$1`, roomID, userID, eventType.Type, defaultType, defaultValue).
			Scan(&hasPower)
		if errors.Is(err, sql.ErrNoRows) {
			err = nil
			hasPower = defaultValue == 0
		}
		return hasPower, err
	} else {
		levels, err := store.GetPowerLevels(ctx, roomID)
		if err != nil {
			return false, err
		}
		return levels.GetUserLevel(userID) >= levels.GetEventLevel(eventType), nil
	}
}
