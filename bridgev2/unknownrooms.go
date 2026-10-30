// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func (br *Bridge) CleanupUnknownRooms(ctx context.Context) {
	log := zerolog.Ctx(ctx).With().Str("action", "cleanup unknown rooms").Logger()
	ctx = log.WithContext(ctx)
	startTime := time.Now()
	users, err := br.GetUsersToStart(ctx)
	if err != nil {
		log.Err(err).Msg("Failed to get users to clean up rooms of")
		return
	}
	portals, err := br.DB.Portal.GetAllWithMXID(ctx)
	if err != nil {
		log.Err(err).Msg("Failed to get portals")
		return
	}
	knownRooms := make(map[id.RoomID]struct{}, len(portals))
	for _, portal := range portals {
		knownRooms[portal.MXID] = struct{}{}
	}
	for _, user := range users {
		knownRooms[user.ManagementRoom] = struct{}{}
		for _, login := range user.GetUserLogins() {
			knownRooms[login.SpaceRoom] = struct{}{}
		}
	}
	var deletedCount, failedCount int
	for _, user := range users {
		lister, ok := user.DoublePuppet(ctx).(MatrixAPIWithRoomListing)
		if !ok {
			log.Warn().Stringer("user_id", user.MXID).Msg("Double puppet doesn't support listing rooms, skipping user")
			continue
		}
		rooms, err := lister.GetJoinedRooms(ctx)
		if err != nil {
			log.Err(err).Stringer("user_id", user.MXID).Msg("Failed to get joined rooms of user")
			failedCount++
			continue
		}
		for _, roomID := range rooms {
			if _, known := knownRooms[roomID]; known {
				continue
			}
			isUnknown, err := br.isUnknownBridgeRoom(ctx, lister, roomID, startTime)
			if err != nil {
				log.Err(err).Stringer("room_id", roomID).Msg("Failed to check if room is an unknown bridge room")
				failedCount++
				continue
			} else if !isUnknown {
				continue
			}
			err = br.Bot.EnsureJoined(ctx, roomID)
			if err == nil {
				err = br.Bot.DeleteRoom(ctx, roomID, true)
			}
			if err != nil {
				log.Err(err).Stringer("room_id", roomID).Msg("Failed to delete unknown room")
				failedCount++
			} else {
				log.Debug().Stringer("room_id", roomID).Msg("Deleted unknown room")
				deletedCount++
			}
		}
	}
	br.DB.KV.Set(ctx, database.KeyUnknownRoomsCleanedUp, "true")
	log.Info().
		Int("deleted_count", deletedCount).
		Int("failed_count", failedCount).
		Msg("Finished cleaning up unknown rooms")
}

func (br *Bridge) isUnknownBridgeRoom(ctx context.Context, intent MatrixAPIWithRoomListing, roomID id.RoomID, startTime time.Time) (bool, error) {
	state, err := intent.GetRoomState(ctx, roomID)
	if err != nil {
		return false, err
	}
	var hasBridgeInfo bool
	var createdAt int64
	for _, evt := range state {
		switch evt.Type {
		case event.StateBridge, event.StateHalfShotBridge:
			if evt.Content.ParseRaw(evt.Type) == nil && evt.Content.AsBridge().BridgeBot == br.Bot.GetMXID() {
				hasBridgeInfo = true
			}
		case event.StateCreate:
			createdAt = evt.Timestamp
		}
	}
	if !hasBridgeInfo || createdAt == 0 || time.UnixMilli(createdAt).After(startTime) {
		return false, nil
	}
	portal, err := br.DB.Portal.GetByMXID(ctx, roomID)
	return portal == nil, err
}
