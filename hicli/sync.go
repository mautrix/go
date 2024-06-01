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
	"strings"

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

	evt *SyncComplete
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

func (h *HiClient) postProcessSyncResponse(ctx context.Context, resp *mautrix.RespSync, since string) {
	h.Crypto.HandleOTKCounts(ctx, &resp.DeviceOTKCount)
	go h.asyncPostProcessSyncResponse(ctx, resp, since)
	syncCtx := ctx.Value(syncContextKey).(*syncContext)
	if syncCtx.shouldWakeupRequestQueue {
		h.WakeupRequestQueue()
	}
	h.firstSyncReceived = true
	h.EventHandler(syncCtx.evt)
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

func receiptsToList(content *event.ReceiptEventContent) []*database.Receipt {
	receiptList := make([]*database.Receipt, 0)
	for eventID, receipts := range *content {
		for receiptType, users := range receipts {
			for userID, receiptInfo := range users {
				receiptList = append(receiptList, &database.Receipt{
					UserID:      userID,
					ReceiptType: receiptType,
					ThreadID:    receiptInfo.ThreadID,
					EventID:     eventID,
					Timestamp:   receiptInfo.Timestamp,
				})
			}
		}
	}
	return receiptList
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
	for _, evt := range room.Ephemeral.Events {
		evt.Type.Class = event.EphemeralEventType
		err = evt.Content.ParseRaw(evt.Type)
		if err != nil {
			zerolog.Ctx(ctx).Debug().Err(err).Msg("Failed to parse ephemeral event content")
			continue
		}
		switch evt.Type {
		case event.EphemeralEventReceipt:
			err = h.DB.Receipt.PutMany(ctx, roomID, receiptsToList(evt.Content.AsReceipt())...)
			if err != nil {
				return fmt.Errorf("failed to save receipts: %w", err)
			}
		case event.EphemeralEventTyping:
			go h.EventHandler(&Typing{
				RoomID:             roomID,
				TypingEventContent: *evt.Content.AsTyping(),
			})
		}
		if evt.Type != event.EphemeralEventReceipt {
			continue
		}
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
			bytes, err2 := sjson.SetBytes(bytes, "body", content.Body)
			if err == nil && err2 == nil {
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

func (h *HiClient) processEvent(ctx context.Context, evt *event.Event, decryptionQueue map[id.SessionID]*database.SessionRequest, checkDB bool) (*database.Event, error) {
	if checkDB {
		dbEvt, err := h.DB.Event.GetByID(ctx, evt.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to check if event %s exists: %w", evt.ID, err)
		} else if dbEvt != nil {
			return dbEvt, nil
		}
	}
	dbEvt := database.MautrixToEvent(evt)
	contentWithoutFallback := removeReplyFallback(evt)
	if contentWithoutFallback != nil {
		dbEvt.Content = contentWithoutFallback
	}
	var decryptionErr error
	if evt.Type == event.EventEncrypted && dbEvt.RedactedBy == "" {
		dbEvt.Decrypted, dbEvt.DecryptedType, decryptionErr = h.decryptEvent(ctx, evt)
		if decryptionErr != nil {
			dbEvt.DecryptionError = decryptionErr.Error()
		}
	} else if evt.Type == event.EventRedaction {
		if evt.Redacts != "" && gjson.GetBytes(evt.Content.VeryRaw, "redacts").Str != evt.Redacts.String() {
			var err error
			evt.Content.VeryRaw, err = sjson.SetBytes(evt.Content.VeryRaw, "redacts", evt.Redacts)
			if err != nil {
				return dbEvt, fmt.Errorf("failed to set redacts field: %w", err)
			}
		}
	}
	_, err := h.DB.Event.Upsert(ctx, dbEvt)
	if err != nil {
		return dbEvt, fmt.Errorf("failed to save event %s: %w", evt.ID, err)
	}
	if decryptionErr != nil && isDecryptionErrorRetryable(decryptionErr) {
		req, ok := decryptionQueue[dbEvt.MegolmSessionID]
		if !ok {
			req = &database.SessionRequest{
				RoomID:    evt.RoomID,
				SessionID: dbEvt.MegolmSessionID,
				Sender:    evt.Sender,
			}
		}
		minIndex, _ := crypto.ParseMegolmMessageIndex(evt.Content.AsEncrypted().MegolmCiphertext)
		req.MinIndex = min(uint32(minIndex), req.MinIndex)
		decryptionQueue[dbEvt.MegolmSessionID] = req
	}
	return dbEvt, err
}

func (h *HiClient) processStateAndTimeline(ctx context.Context, room *database.Room, state *mautrix.SyncEventsList, timeline *mautrix.SyncTimeline, summary *mautrix.LazyLoadSummary) error {
	updatedRoom := &database.Room{
		ID: room.ID,

		SortingTimestamp: room.SortingTimestamp,
		NameQuality:      room.NameQuality,
	}
	heroesChanged := false
	if summary.Heroes == nil && summary.JoinedMemberCount == nil && summary.InvitedMemberCount == nil {
		summary = room.LazyLoadSummary
	} else if room.LazyLoadSummary == nil ||
		!slices.Equal(summary.Heroes, room.LazyLoadSummary.Heroes) ||
		!intPtrEqual(summary.JoinedMemberCount, room.LazyLoadSummary.JoinedMemberCount) ||
		!intPtrEqual(summary.InvitedMemberCount, room.LazyLoadSummary.InvitedMemberCount) {
		updatedRoom.LazyLoadSummary = summary
		heroesChanged = true
	}
	decryptionQueue := make(map[id.SessionID]*database.SessionRequest)
	processNewEvent := func(evt *event.Event, isTimeline bool) (database.EventRowID, error) {
		evt.RoomID = room.ID
		dbEvt, err := h.processEvent(ctx, evt, decryptionQueue, false)
		if err != nil {
			return -1, err
		}
		if isTimeline {
			if dbEvt.CanUseForPreview() {
				updatedRoom.PreviewEventRowID = dbEvt.RowID
			}
			updatedRoom.BumpSortingTimestamp(dbEvt)
		}
		if evt.StateKey != nil {
			var membership event.Membership
			if evt.Type == event.StateMember {
				membership = event.Membership(gjson.GetBytes(evt.Content.VeryRaw, "membership").Str)
				if summary != nil && slices.Contains(summary.Heroes, id.UserID(*evt.StateKey)) {
					heroesChanged = true
				}
			} else if evt.Type == event.StateElementFunctionalMembers {
				heroesChanged = true
			}
			err = h.DB.CurrentState.Set(ctx, room.ID, evt.Type, *evt.StateKey, dbEvt.RowID, membership)
			if err != nil {
				return -1, fmt.Errorf("failed to save current state event ID %s for %s/%s: %w", evt.ID, evt.Type.Type, *evt.StateKey, err)
			}
			processImportantEvent(ctx, evt, room, updatedRoom)
		}
		return dbEvt.RowID, nil
	}
	var err error
	for _, evt := range state.Events {
		evt.Type.Class = event.StateEventType
		_, err = processNewEvent(evt, false)
		if err != nil {
			return err
		}
	}
	var timelineRowTuples []database.TimelineRowTuple
	if len(timeline.Events) > 0 {
		timelineIDs := make([]database.EventRowID, len(timeline.Events))
		for i, evt := range timeline.Events {
			if evt.StateKey != nil {
				evt.Type.Class = event.StateEventType
			} else {
				evt.Type.Class = event.MessageEventType
			}
			timelineIDs[i], err = processNewEvent(evt, true)
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
			updatedRoom.PrevBatch = timeline.PrevBatch
			h.paginationInterrupterLock.Lock()
			if interrupt, ok := h.paginationInterrupter[room.ID]; ok {
				interrupt(ErrTimelineReset)
			}
			h.paginationInterrupterLock.Unlock()
		}
		timelineRowTuples, err = h.DB.Timeline.Append(ctx, room.ID, timelineIDs)
		if err != nil {
			return fmt.Errorf("failed to append timeline: %w", err)
		}
	}
	// Calculate name from participants if participants changed and current name was generated from participants, or if the room name was unset
	if (heroesChanged && updatedRoom.NameQuality <= database.NameQualityParticipants) || updatedRoom.NameQuality == database.NameQualityNil {
		name, err := h.calculateRoomParticipantName(ctx, room.ID, summary)
		if err != nil {
			return fmt.Errorf("failed to calculate room name: %w", err)
		}
		updatedRoom.Name = &name
		updatedRoom.NameQuality = database.NameQualityParticipants
	}
	if timeline.PrevBatch != "" && room.PrevBatch == "" {
		updatedRoom.PrevBatch = timeline.PrevBatch
	}
	roomChanged := updatedRoom.CheckChangesAndCopyInto(room)
	if roomChanged {
		err = h.DB.Room.Upsert(ctx, updatedRoom)
		if err != nil {
			return fmt.Errorf("failed to save room data: %w", err)
		}
	}
	if roomChanged || len(timelineRowTuples) > 0 {
		ctx.Value(syncContextKey).(*syncContext).evt.Rooms[room.ID] = &SyncRoom{
			Meta:     room,
			Timeline: timelineRowTuples,
			Reset:    timeline.Limited,
		}
	}
	return nil
}

func joinMemberNames(names []string, totalCount int) string {
	if len(names) == 1 {
		return names[0]
	} else if len(names) < 5 || (len(names) == 5 && totalCount <= 6) {
		return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
	} else {
		return fmt.Sprintf("%s and %d others", strings.Join(names[:4], ", "), totalCount-5)
	}
}

func (h *HiClient) calculateRoomParticipantName(ctx context.Context, roomID id.RoomID, summary *mautrix.LazyLoadSummary) (string, error) {
	if summary == nil || len(summary.Heroes) == 0 {
		return "Empty room", nil
	}
	var functionalMembers []id.UserID
	functionalMembersEvt, err := h.DB.CurrentState.Get(ctx, roomID, event.StateElementFunctionalMembers, "")
	if err != nil {
		return "", fmt.Errorf("failed to get %s event: %w", event.StateElementFunctionalMembers.Type, err)
	} else if functionalMembersEvt != nil {
		mautrixEvt := functionalMembersEvt.AsRawMautrix()
		_ = mautrixEvt.Content.ParseRaw(mautrixEvt.Type)
		content, ok := mautrixEvt.Content.Parsed.(*event.ElementFunctionalMembersContent)
		if ok {
			functionalMembers = content.FunctionalMembers
		}
	}
	var members, leftMembers []string
	var memberCount int
	if summary.JoinedMemberCount != nil && *summary.JoinedMemberCount > 0 {
		memberCount = *summary.JoinedMemberCount
	} else if summary.InvitedMemberCount != nil {
		memberCount = *summary.InvitedMemberCount
	}
	for _, hero := range summary.Heroes {
		if slices.Contains(functionalMembers, hero) {
			memberCount--
			continue
		} else if len(members) >= 5 {
			break
		}
		heroEvt, err := h.DB.CurrentState.Get(ctx, roomID, event.StateMember, hero.String())
		if err != nil {
			return "", fmt.Errorf("failed to get %s's member event: %w", hero, err)
		}
		results := gjson.GetManyBytes(heroEvt.Content, "membership", "displayname")
		name := results[1].Str
		if name == "" {
			name = hero.String()
		}
		if results[0].Str == "join" || results[0].Str == "invite" {
			members = append(members, name)
		} else {
			leftMembers = append(leftMembers, name)
		}
	}
	if len(members) > 0 {
		return joinMemberNames(members, memberCount), nil
	} else if len(leftMembers) > 0 {
		return fmt.Sprintf("Empty room (was %s)", joinMemberNames(leftMembers, memberCount)), nil
	} else {
		return "Empty room", nil
	}
}

func intPtrEqual(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func processImportantEvent(ctx context.Context, evt *event.Event, existingRoomData, updatedRoom *database.Room) (roomDataChanged bool) {
	if evt.StateKey == nil {
		return
	}
	switch evt.Type {
	case event.StateCreate, event.StateRoomName, event.StateCanonicalAlias, event.StateRoomAvatar, event.StateTopic, event.StateEncryption:
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
		updatedRoom.CreationContent, _ = evt.Content.Parsed.(*event.CreateEventContent)
	case event.StateEncryption:
		newEncryption, _ := evt.Content.Parsed.(*event.EncryptionEventContent)
		if existingRoomData.EncryptionEvent == nil || existingRoomData.EncryptionEvent.Algorithm == newEncryption.Algorithm {
			updatedRoom.EncryptionEvent = newEncryption
		}
	case event.StateRoomName:
		content, ok := evt.Content.Parsed.(*event.RoomNameEventContent)
		if ok {
			updatedRoom.Name = &content.Name
			updatedRoom.NameQuality = database.NameQualityExplicit
			if content.Name == "" {
				if updatedRoom.CanonicalAlias != nil && *updatedRoom.CanonicalAlias != "" {
					updatedRoom.Name = (*string)(updatedRoom.CanonicalAlias)
					updatedRoom.NameQuality = database.NameQualityCanonicalAlias
				} else if existingRoomData.CanonicalAlias != nil && *existingRoomData.CanonicalAlias != "" {
					updatedRoom.Name = (*string)(existingRoomData.CanonicalAlias)
					updatedRoom.NameQuality = database.NameQualityCanonicalAlias
				} else {
					updatedRoom.NameQuality = database.NameQualityNil
				}
			}
		}
	case event.StateCanonicalAlias:
		content, ok := evt.Content.Parsed.(*event.CanonicalAliasEventContent)
		if ok {
			updatedRoom.CanonicalAlias = &content.Alias
			if updatedRoom.NameQuality <= database.NameQualityCanonicalAlias {
				updatedRoom.Name = (*string)(&content.Alias)
				updatedRoom.NameQuality = database.NameQualityCanonicalAlias
				if content.Alias == "" {
					updatedRoom.NameQuality = database.NameQualityNil
				}
			}
		}
	case event.StateRoomAvatar:
		content, ok := evt.Content.Parsed.(*event.RoomAvatarEventContent)
		if ok {
			updatedRoom.Avatar = &content.URL
		}
	case event.StateTopic:
		content, ok := evt.Content.Parsed.(*event.TopicEventContent)
		if ok {
			updatedRoom.Topic = &content.Topic
		}
	}
	return
}
