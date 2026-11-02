// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/id"
)

func (br *Bridge) startUnknownRoomCleanup(ctx context.Context) {
	if br.Background || !br.Config.CleanupUnknownRooms || br.DB.KV.Get(ctx, database.KeyUnknownRoomsCleanedUp) == "true" {
		return
	}
	log := zerolog.Ctx(ctx).With().Str("action", "cleanup unknown rooms").Logger()
	ctx = log.WithContext(ctx)
	rooms, err := br.findUnknownRooms(ctx)
	if err != nil {
		log.Err(err).Msg("Failed to find unknown rooms")
		return
	}
	log.Info().Int("room_count", len(rooms)).Msg("Found unknown rooms to delete")
	go br.deleteUnknownRooms(log.WithContext(br.BackgroundCtx), rooms)
}

func (br *Bridge) findUnknownRooms(ctx context.Context) ([]id.RoomID, error) {
	lister, ok := br.Bot.(MatrixAPIWithRoomListing)
	if !ok {
		zerolog.Ctx(ctx).Warn().Msg("Bridge bot doesn't support listing rooms, skipping cleanup")
		return nil, nil
	}
	rooms, err := lister.GetJoinedRooms(ctx)
	if err != nil {
		return nil, err
	}
	knownRooms, err := br.getKnownRooms(ctx)
	if err != nil {
		return nil, err
	}
	unknownRooms := make([]id.RoomID, 0)
	for _, roomID := range rooms {
		if _, known := knownRooms[roomID]; !known {
			unknownRooms = append(unknownRooms, roomID)
		}
	}
	return unknownRooms, nil
}

func (br *Bridge) deleteUnknownRooms(ctx context.Context, rooms []id.RoomID) {
	log := zerolog.Ctx(ctx)
	var deletedCount, failedCount int
	for _, roomID := range rooms {
		if ctx.Err() != nil {
			log.Warn().Msg("Bridge is stopping, cleanup will continue on next start")
			return
		}
		portal, err := br.DB.Portal.GetByMXID(ctx, roomID)
		if err != nil {
			log.Err(err).Stringer("room_id", roomID).Msg("Failed to check if room is a portal")
			failedCount++
			continue
		} else if portal != nil {
			continue
		}
		err = br.Bot.DeleteRoom(ctx, roomID, true)
		if err != nil {
			log.Err(err).Stringer("room_id", roomID).Msg("Failed to delete unknown room")
			failedCount++
		} else {
			log.Debug().Stringer("room_id", roomID).Msg("Deleted unknown room")
			deletedCount++
		}
	}
	br.DB.KV.Set(ctx, database.KeyUnknownRoomsCleanedUp, "true")
	log.Info().
		Int("deleted_count", deletedCount).
		Int("failed_count", failedCount).
		Msg("Finished cleaning up unknown rooms")
}

func (br *Bridge) getKnownRooms(ctx context.Context) (map[id.RoomID]struct{}, error) {
	portals, err := br.DB.Portal.GetAllWithMXID(ctx)
	if err != nil {
		return nil, err
	}
	users, err := br.DB.User.GetAll(ctx)
	if err != nil {
		return nil, err
	}
	knownRooms := make(map[id.RoomID]struct{}, len(portals)+len(users))
	for _, portal := range portals {
		knownRooms[portal.MXID] = struct{}{}
	}
	for _, user := range users {
		if user.ManagementRoom != "" {
			knownRooms[user.ManagementRoom] = struct{}{}
		}
		logins, err := br.DB.UserLogin.GetAllForUser(ctx, user.MXID)
		if err != nil {
			return nil, err
		}
		for _, login := range logins {
			if login.SpaceRoom != "" {
				knownRooms[login.SpaceRoom] = struct{}{}
			}
		}
	}
	return knownRooms, nil
}
