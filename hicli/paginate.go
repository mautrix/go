// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package hicli

import (
	"context"
	"errors"
	"fmt"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/hicli/database"
	"maunium.net/go/mautrix/id"
)

var ErrPaginationAlreadyInProgress = errors.New("pagination is already in progress")

func (h *HiClient) GetEventsByRowIDs(ctx context.Context, rowIDs []database.EventRowID) ([]*database.Event, error) {
	events, err := h.DB.Event.GetByRowIDs(ctx, rowIDs...)
	if err != nil {
		return nil, err
	} else if len(events) == 0 {
		return events, nil
	}
	firstRoomID := events[0].RoomID
	allInSameRoom := true
	for _, evt := range events {
		if evt.RoomID != firstRoomID {
			allInSameRoom = false
			break
		}
	}
	if allInSameRoom {
		err = h.DB.Event.FillLastEditRowIDs(ctx, firstRoomID, events)
		if err != nil {
			return events, fmt.Errorf("failed to fill last edit row IDs: %w", err)
		}
		err = h.DB.Event.FillReactionCounts(ctx, firstRoomID, events)
		if err != nil {
			return events, fmt.Errorf("failed to fill reaction counts: %w", err)
		}
	} else {
		// TODO slow path where events are collected and filling is done one room at a time?
	}
	return events, nil
}

func (h *HiClient) GetEvent(ctx context.Context, roomID id.RoomID, eventID id.EventID) (*database.Event, error) {
	if evt, err := h.DB.Event.GetByID(ctx, eventID); err != nil {
		return nil, fmt.Errorf("failed to get event from database: %w", err)
	} else if evt != nil {
		return evt, nil
	} else if serverEvt, err := h.Client.GetEvent(ctx, roomID, eventID); err != nil {
		return nil, fmt.Errorf("failed to get event from server: %w", err)
	} else {
		return h.processEvent(ctx, serverEvt, nil, false)
	}
}

func (h *HiClient) Paginate(ctx context.Context, roomID id.RoomID, maxTimelineID database.TimelineRowID, limit int) ([]*database.Event, error) {
	evts, err := h.DB.Timeline.Get(ctx, roomID, limit, maxTimelineID)
	if err != nil {
		return nil, err
	} else if len(evts) > 0 {
		return evts, nil
	} else {
		return h.PaginateServer(ctx, roomID, limit)
	}
}

func (h *HiClient) PaginateServer(ctx context.Context, roomID id.RoomID, limit int) ([]*database.Event, error) {
	ctx, cancel := context.WithCancelCause(ctx)
	h.paginationInterrupterLock.Lock()
	if _, alreadyPaginating := h.paginationInterrupter[roomID]; alreadyPaginating {
		h.paginationInterrupterLock.Unlock()
		return nil, ErrPaginationAlreadyInProgress
	}
	h.paginationInterrupter[roomID] = cancel
	h.paginationInterrupterLock.Unlock()
	defer func() {
		h.paginationInterrupterLock.Lock()
		delete(h.paginationInterrupter, roomID)
		h.paginationInterrupterLock.Unlock()
	}()

	room, err := h.DB.Room.Get(ctx, roomID)
	if err != nil {
		return nil, fmt.Errorf("failed to get room from database: %w", err)
	}
	resp, err := h.Client.Messages(ctx, roomID, room.PrevBatch, "", mautrix.DirectionBackward, nil, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get messages from server: %w", err)
	}
	events := make([]*database.Event, len(resp.Chunk))
	wakeupSessionRequests := false
	err = h.DB.DoTxn(ctx, nil, func(ctx context.Context) error {
		if err = ctx.Err(); err != nil {
			return err
		}
		eventRowIDs := make([]database.EventRowID, len(resp.Chunk))
		decryptionQueue := make(map[id.SessionID]*database.SessionRequest)
		for i, evt := range resp.Chunk {
			events[i], err = h.processEvent(ctx, evt, decryptionQueue, true)
			if err != nil {
				return err
			}
			eventRowIDs[i] = events[i].RowID
		}
		wakeupSessionRequests = len(decryptionQueue) > 0
		for _, entry := range decryptionQueue {
			err = h.DB.SessionRequest.Put(ctx, entry)
			if err != nil {
				return fmt.Errorf("failed to save session request for %s: %w", entry.SessionID, err)
			}
		}
		err = h.DB.Event.FillLastEditRowIDs(ctx, roomID, events)
		if err != nil {
			return fmt.Errorf("failed to fill last edit row IDs: %w", err)
		}
		err = h.DB.Room.SetPrevBatch(ctx, room.ID, resp.End)
		if err != nil {
			return fmt.Errorf("failed to set prev_batch: %w", err)
		}
		var tuples []database.TimelineRowTuple
		tuples, err = h.DB.Timeline.Prepend(ctx, room.ID, eventRowIDs)
		if err != nil {
			return fmt.Errorf("failed to prepend events to timeline: %w", err)
		}
		for i, evt := range events {
			evt.TimelineRowID = tuples[i].Timeline
		}
		return nil
	})
	if err == nil && wakeupSessionRequests {
		h.WakeupRequestQueue()
	}
	return events, err
}
