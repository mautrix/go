// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package database

import (
	"context"
	"database/sql"
	"time"

	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/jsontime"

	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// Deprecated: use [event.DisappearingType]
type DisappearingType = event.DisappearingType

// Deprecated: use constants in event package
const (
	DisappearingTypeNone      = event.DisappearingTypeNone
	DisappearingTypeAfterRead = event.DisappearingTypeAfterRead
	DisappearingTypeAfterSend = event.DisappearingTypeAfterSend
)

// DisappearingSetting represents a disappearing message timer setting
// by combining a type with a timer and an optional start timestamp.
type DisappearingSetting struct {
	Type        event.DisappearingType
	Timer       time.Duration
	DisappearAt time.Time
}

func DisappearingSettingFromEvent(evt *event.BeeperDisappearingTimer) DisappearingSetting {
	if evt == nil || evt.Type == event.DisappearingTypeNone {
		return DisappearingSetting{}
	}
	return DisappearingSetting{
		Type:  evt.Type,
		Timer: evt.Timer.Duration,
	}
}

func (ds DisappearingSetting) Normalize() DisappearingSetting {
	if ds.Type == event.DisappearingTypeNone {
		ds.Timer = 0
	} else if ds.Timer == 0 {
		ds.Type = event.DisappearingTypeNone
	}
	return ds
}

func (ds DisappearingSetting) StartingAt(start time.Time) DisappearingSetting {
	ds.DisappearAt = start.Add(ds.Timer)
	return ds
}

func (ds DisappearingSetting) ToEventContent() *event.BeeperDisappearingTimer {
	if ds.Type == event.DisappearingTypeNone || ds.Timer == 0 {
		return &event.BeeperDisappearingTimer{}
	}
	return &event.BeeperDisappearingTimer{
		Type:  ds.Type,
		Timer: jsontime.MS(ds.Timer),
	}
}

type DisappearingMessageQuery struct {
	BridgeID networkid.BridgeID
	*dbutil.QueryHelper[*DisappearingMessage]
}

type DisappearingMessage struct {
	BridgeID  networkid.BridgeID
	RoomID    id.RoomID
	EventID   id.EventID
	Timestamp time.Time
	DisappearingSetting
}

const (
	upsertDisappearingMessageQuery = `
		INSERT INTO disappearing_message (bridge_id, mx_room, mxid, timestamp, type, timer, disappear_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (bridge_id, mxid) DO UPDATE SET timer=excluded.timer, disappear_at=excluded.disappear_at
	`
	startDisappearingMessagesQuery = `
		UPDATE disappearing_message
		SET disappear_at=$1 + timer
		WHERE bridge_id=$2 AND mx_room=$3 AND disappear_at IS NULL AND type='after_read' AND timestamp<=$4
		RETURNING bridge_id, mx_room, mxid, timestamp, type, timer, disappear_at
	`
	getUpcomingDisappearingMessagesQuery = `
		SELECT bridge_id, mx_room, mxid, timestamp, type, timer, disappear_at
		FROM disappearing_message WHERE bridge_id = $1 AND disappear_at IS NOT NULL AND disappear_at < $2
		ORDER BY disappear_at LIMIT $3
	`
	deleteDisappearingMessageQuery = `
		DELETE FROM disappearing_message WHERE bridge_id=$1 AND mxid=$2
	`
)

func (dmq *DisappearingMessageQuery) Put(ctx context.Context, dm *DisappearingMessage) error {
	ensureBridgeIDMatches(&dm.BridgeID, dmq.BridgeID)
	return dmq.Exec(ctx, upsertDisappearingMessageQuery, dm.sqlVariables()...)
}

func (dmq *DisappearingMessageQuery) StartAllBefore(ctx context.Context, roomID id.RoomID, beforeTS time.Time) ([]*DisappearingMessage, error) {
	return dmq.QueryMany(ctx, startDisappearingMessagesQuery, time.Now().UnixNano(), dmq.BridgeID, roomID, beforeTS.UnixNano())
}

func (dmq *DisappearingMessageQuery) GetUpcoming(ctx context.Context, duration time.Duration, limit int) ([]*DisappearingMessage, error) {
	return dmq.QueryMany(ctx, getUpcomingDisappearingMessagesQuery, dmq.BridgeID, time.Now().Add(duration).UnixNano(), limit)
}

func (dmq *DisappearingMessageQuery) Delete(ctx context.Context, eventID id.EventID) error {
	return dmq.Exec(ctx, deleteDisappearingMessageQuery, dmq.BridgeID, eventID)
}

func (d *DisappearingMessage) Scan(row dbutil.Scannable) (*DisappearingMessage, error) {
	var timestamp int64
	var disappearAt sql.NullInt64
	err := row.Scan(&d.BridgeID, &d.RoomID, &d.EventID, &timestamp, &d.Type, &d.Timer, &disappearAt)
	if err != nil {
		return nil, err
	}
	if disappearAt.Valid {
		d.DisappearAt = time.Unix(0, disappearAt.Int64)
	}
	d.Timestamp = time.Unix(0, timestamp)
	return d, nil
}

func (d *DisappearingMessage) sqlVariables() []any {
	return []any{d.BridgeID, d.RoomID, d.EventID, d.Timestamp.UnixNano(), d.Type, d.Timer, dbutil.ConvertedPtr(d.DisappearAt, time.Time.UnixNano)}
}
