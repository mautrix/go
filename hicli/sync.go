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

	"github.com/rs/zerolog"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"go.mau.fi/util/exzerolog"
	"golang.org/x/exp/slices"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/hicli/database"
	"maunium.net/go/mautrix/id"
)

type syncContext struct {
	shouldWakeupRequestQueue bool
}

func (h *HiClient) preProcessSyncResponse(ctx context.Context, resp *mautrix.RespSync, since string) error {
	log := zerolog.Ctx(ctx)
	postponedToDevices := resp.ToDevice.Events[:0]
	for _, evt := range resp.ToDevice.Events {
		evt.Type.Class = event.ToDeviceEventType
		err := evt.Content.ParseRaw(evt.Type)
		if err != nil {
			log.Warn().Err(err).
				Stringer("event_type", &evt.Type).
				Stringer("sender", evt.Sender).
				Msg("Failed to parse to-device event, skipping")
			continue
		}

		switch content := evt.Content.Parsed.(type) {
		case *event.EncryptedEventContent:
			h.Crypto.HandleEncryptedEvent(ctx, evt)
		case *event.RoomKeyWithheldEventContent:
			h.Crypto.HandleRoomKeyWithheld(ctx, content)
		default:
			postponedToDevices = append(postponedToDevices, evt)
		}
	}
	resp.ToDevice.Events = postponedToDevices

	return nil
}

func (h *HiClient) postProcessSyncResponse(ctx context.Context, resp *mautrix.RespSync, since string) error {
	h.Crypto.HandleOTKCounts(ctx, &resp.DeviceOTKCount)
	go h.asyncPostProcessSyncResponse(ctx, resp, since)
	if ctx.Value(syncContextKey).(*syncContext).shouldWakeupRequestQueue {
		h.WakeupRequestQueue()
	}
	return nil
}

func (h *HiClient) asyncPostProcessSyncResponse(ctx context.Context, resp *mautrix.RespSync, since string) {
	for _, evt := range resp.ToDevice.Events {
		switch content := evt.Content.Parsed.(type) {
		case *event.SecretRequestEventContent:
			h.Crypto.HandleSecretRequest(ctx, evt.Sender, content)
		case *event.RoomKeyRequestEventContent:
			h.Crypto.HandleRoomKeyRequest(ctx, evt.Sender, content)
		}
	}
}

func (h *HiClient) processSyncResponse(ctx context.Context, resp *mautrix.RespSync, since string) error {
	if len(resp.DeviceLists.Changed) > 0 {
		zerolog.Ctx(ctx).Debug().
			Array("users", exzerolog.ArrayOfStringers(resp.DeviceLists.Changed)).
			Msg("Marking changed device lists for tracked users as outdated")
		err := h.Crypto.CryptoStore.MarkTrackedUsersOutdated(ctx, resp.DeviceLists.Changed)
		if err != nil {
			return fmt.Errorf("failed to mark changed device lists as outdated: %w", err)
		}
		ctx.Value(syncContextKey).(*syncContext).shouldWakeupRequestQueue = true
	}

	for _, evt := range resp.AccountData.Events {
		evt.Type.Class = event.AccountDataEventType
		err := h.DB.AccountData.Put(ctx, h.Account.UserID, evt.Type, evt.Content.VeryRaw)
		if err != nil {
			return fmt.Errorf("failed to save account data event %s: %w", evt.Type.Type, err)
		}
	}
	for roomID, room := range resp.Rooms.Join {
		err := h.processSyncJoinedRoom(ctx, roomID, room)
		if err != nil {
			return fmt.Errorf("failed to process joined room %s: %w", roomID, err)
		}
	}
	for roomID, room := range resp.Rooms.Leave {
		err := h.processSyncLeftRoom(ctx, roomID, room)
		if err != nil {
			return fmt.Errorf("failed to process left room %s: %w", roomID, err)
		}
	}
	h.Account.NextBatch = resp.NextBatch
	err := h.DB.Account.PutNextBatch(ctx, h.Account.UserID, resp.NextBatch)
	if err != nil {
		return fmt.Errorf("failed to save next_batch: %w", err)
	}
	return nil
}

func (h *HiClient) processSyncJoinedRoom(ctx context.Context, roomID id.RoomID, room *mautrix.SyncJoinedRoom) error {
	existingRoomData, err := h.DB.Room.Get(ctx, roomID)
	if err != nil {
		return fmt.Errorf("failed to get room data: %w", err)
	} else if existingRoomData == nil {
		err = h.DB.Room.CreateRow(ctx, roomID)
		if err != nil {
			return fmt.Errorf("failed to ensure room row exists: %w", err)
		}
		existingRoomData = &database.Room{ID: roomID}
	}

	for _, evt := range room.AccountData.Events {
		evt.Type.Class = event.AccountDataEventType
		evt.RoomID = roomID
		err = h.DB.AccountData.PutRoom(ctx, h.Account.UserID, roomID, evt.Type, evt.Content.VeryRaw)
		if err != nil {
			return fmt.Errorf("failed to save account data event %s: %w", evt.Type.Type, err)
		}
	}
	err = h.processStateAndTimeline(ctx, existingRoomData, &room.State, &room.Timeline, &room.Summary)
	if err != nil {
		return err
	}
	return nil
}

func (h *HiClient) processSyncLeftRoom(ctx context.Context, roomID id.RoomID, room *mautrix.SyncLeftRoom) error {
	existingRoomData, err := h.DB.Room.Get(ctx, roomID)
	if err != nil {
		return fmt.Errorf("failed to get room data: %w", err)
	} else if existingRoomData == nil {
		return nil
	}
	return h.processStateAndTimeline(ctx, existingRoomData, &room.State, &room.Timeline, &room.Summary)
}

func isDecryptionErrorRetryable(err error) bool {
	return errors.Is(err, crypto.NoSessionFound) || errors.Is(err, olm.UnknownMessageIndex) || errors.Is(err, crypto.ErrGroupSessionWithheld)
}

func removeReplyFallback(evt *event.Event) []byte {
	content, ok := evt.Content.Parsed.(*event.MessageEventContent)
	if ok && content.RelatesTo.GetReplyTo() != "" {
		prevFormattedBody := content.FormattedBody
		content.RemoveReplyFallback()
		if content.FormattedBody != prevFormattedBody {
			bytes, err := sjson.SetBytes(evt.Content.VeryRaw, "formatted_body", content.FormattedBody)
			if err == nil {
				return bytes
			}
			bytes, err = sjson.SetBytes(evt.Content.VeryRaw, "body", content.Body)
			if err == nil {
				return bytes
			}
		}
	}
	return nil
}

func (h *HiClient) decryptEvent(ctx context.Context, evt *event.Event) ([]byte, string, error) {
	err := evt.Content.ParseRaw(evt.Type)
	if err != nil && !errors.Is(err, event.ErrContentAlreadyParsed) {
		return nil, "", err
	}
	decrypted, err := h.Crypto.DecryptMegolmEvent(ctx, evt)
	if err != nil {
		return nil, "", err
	}
	withoutFallback := removeReplyFallback(decrypted)
	if withoutFallback != nil {
		return withoutFallback, decrypted.Type.Type, nil
	}
	return decrypted.Content.VeryRaw, decrypted.Type.Type, nil
}

func (h *HiClient) processStateAndTimeline(ctx context.Context, room *database.Room, state *mautrix.SyncEventsList, timeline *mautrix.SyncTimeline, summary *mautrix.LazyLoadSummary) error {
	decryptionQueue := make(map[id.SessionID]*database.SessionRequest)
	roomDataChanged := false
	processEvent := func(evt *event.Event) (database.MassInsertableRowID, error) {
		evt.RoomID = room.ID
		dbEvt := database.MautrixToEvent(evt)
		contentWithoutFallback := removeReplyFallback(evt)
		if contentWithoutFallback != nil {
			dbEvt.Content = contentWithoutFallback
		}
		var decryptionErr error
		if evt.Type == event.EventEncrypted {
			dbEvt.Decrypted, dbEvt.DecryptedType, decryptionErr = h.decryptEvent(ctx, evt)
			if decryptionErr != nil {
				dbEvt.DecryptionError = decryptionErr.Error()
			}
		}
		rowID, err := h.DB.Event.Upsert(ctx, dbEvt)
		if err != nil {
			return -1, fmt.Errorf("failed to save event %s: %w", evt.ID, err)
		}
		if decryptionErr != nil && isDecryptionErrorRetryable(decryptionErr) {
			req, ok := decryptionQueue[dbEvt.MegolmSessionID]
			if !ok {
				req = &database.SessionRequest{
					RoomID:    room.ID,
					SessionID: dbEvt.MegolmSessionID,
					Sender:    evt.Sender,
				}
			}
			minIndex, _ := crypto.ParseMegolmMessageIndex(evt.Content.AsEncrypted().MegolmCiphertext)
			req.MinIndex = min(uint32(minIndex), req.MinIndex)
			decryptionQueue[dbEvt.MegolmSessionID] = req
		}
		if evt.StateKey != nil {
			var membership event.Membership
			if evt.Type == event.StateMember {
				membership = event.Membership(gjson.GetBytes(evt.Content.VeryRaw, "membership").Str)
			}
			err = h.DB.CurrentState.Set(ctx, room.ID, evt.Type, *evt.StateKey, rowID, membership)
			if err != nil {
				return -1, fmt.Errorf("failed to save current state event ID %s for %s/%s: %w", evt.ID, evt.Type.Type, *evt.StateKey, err)
			}
			roomDataChanged = processImportantEvent(ctx, evt, room) || roomDataChanged
		}
		return database.MassInsertableRowID(rowID), nil
	}
	var err error
	for _, evt := range state.Events {
		evt.Type.Class = event.StateEventType
		_, err = processEvent(evt)
		if err != nil {
			return err
		}
	}
	if len(timeline.Events) > 0 {
		timelineIDs := make([]database.MassInsertableRowID, len(timeline.Events))
		for i, evt := range timeline.Events {
			if evt.StateKey != nil {
				evt.Type.Class = event.StateEventType
			} else {
				evt.Type.Class = event.MessageEventType
			}
			timelineIDs[i], err = processEvent(evt)
			if err != nil {
				return err
			}
		}
		for _, entry := range decryptionQueue {
			err = h.DB.SessionRequest.Put(ctx, entry)
			if err != nil {
				return fmt.Errorf("failed to save session request for %s: %w", entry.SessionID, err)
			}
		}
		if len(decryptionQueue) > 0 {
			ctx.Value(syncContextKey).(*syncContext).shouldWakeupRequestQueue = true
		}
		if timeline.Limited {
			err = h.DB.Timeline.Clear(ctx, room.ID)
			if err != nil {
				return fmt.Errorf("failed to clear old timeline: %w", err)
			}
		}
		err = h.DB.Timeline.Append(ctx, room.ID, timelineIDs)
		if err != nil {
			return fmt.Errorf("failed to append timeline: %w", err)
		}
	}
	if timeline.PrevBatch != "" && room.PrevBatch == "" {
		room.PrevBatch = timeline.PrevBatch
		roomDataChanged = true
	}
	if summary.Heroes != nil {
		roomDataChanged = roomDataChanged || room.LazyLoadSummary == nil ||
			!slices.Equal(summary.Heroes, room.LazyLoadSummary.Heroes) ||
			!intPtrEqual(summary.JoinedMemberCount, room.LazyLoadSummary.JoinedMemberCount) ||
			!intPtrEqual(summary.InvitedMemberCount, room.LazyLoadSummary.InvitedMemberCount)
		room.LazyLoadSummary = summary
	}
	if roomDataChanged {
		err = h.DB.Room.Upsert(ctx, room)
		if err != nil {
			return fmt.Errorf("failed to save room data: %w", err)
		}
	}
	return nil
}

func intPtrEqual(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func processImportantEvent(ctx context.Context, evt *event.Event, existingRoomData *database.Room) (roomDataChanged bool) {
	if evt.StateKey == nil {
		return
	}
	switch evt.Type {
	case event.StateCreate, event.StateRoomName, event.StateRoomAvatar, event.StateTopic, event.StateEncryption:
		if *evt.StateKey != "" {
			return
		}
	default:
		return
	}
	err := evt.Content.ParseRaw(evt.Type)
	if err != nil {
		zerolog.Ctx(ctx).Warn().Err(err).
			Stringer("event_type", &evt.Type).
			Stringer("event_id", evt.ID).
			Msg("Failed to parse state event, skipping")
		return
	}
	switch evt.Type {
	case event.StateCreate:
		if existingRoomData.CreationContent == nil {
			roomDataChanged = true
		}
		existingRoomData.CreationContent, _ = evt.Content.Parsed.(*event.CreateEventContent)
	case event.StateEncryption:
		newEncryption, _ := evt.Content.Parsed.(*event.EncryptionEventContent)
		if existingRoomData.EncryptionEvent == nil || existingRoomData.EncryptionEvent.Algorithm == newEncryption.Algorithm {
			roomDataChanged = true
			existingRoomData.EncryptionEvent = newEncryption
		}
	case event.StateRoomName:
		content, ok := evt.Content.Parsed.(*event.RoomNameEventContent)
		if ok {
			roomDataChanged = existingRoomData.Name == nil || *existingRoomData.Name != content.Name
			existingRoomData.Name = &content.Name
		}
	case event.StateRoomAvatar:
		content, ok := evt.Content.Parsed.(*event.RoomAvatarEventContent)
		if ok {
			roomDataChanged = existingRoomData.Avatar == nil || *existingRoomData.Avatar != content.URL
			existingRoomData.Avatar = &content.URL
		}
	case event.StateTopic:
		content, ok := evt.Content.Parsed.(*event.TopicEventContent)
		if ok {
			roomDataChanged = existingRoomData.Topic == nil || *existingRoomData.Topic != content.Topic
			existingRoomData.Topic = &content.Topic
		}
	}
	return
}
