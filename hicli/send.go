// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package hicli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/hicli/database"
	"maunium.net/go/mautrix/id"
)

func (h *HiClient) Send(ctx context.Context, roomID id.RoomID, evtType event.Type, content any) (*database.Event, error) {
	roomMeta, err := h.DB.Room.Get(ctx, roomID)
	if err != nil {
		return nil, fmt.Errorf("failed to get room metadata: %w", err)
	} else if roomMeta == nil {
		return nil, fmt.Errorf("unknown room")
	}
	var decryptedType event.Type
	var decryptedContent json.RawMessage
	var megolmSessionID id.SessionID
	if roomMeta.EncryptionEvent != nil && evtType != event.EventReaction {
		decryptedType = evtType
		decryptedContent, err = json.Marshal(content)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal event content: %w", err)
		}
		encryptedContent, err := h.Encrypt(ctx, roomMeta, evtType, content)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt event: %w", err)
		}
		megolmSessionID = encryptedContent.SessionID
		content = encryptedContent
		evtType = event.EventEncrypted
	}
	mainContent, err := json.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal event content: %w", err)
	}
	var zero database.EventRowID
	txnID := "hicli-" + h.Client.TxnID()
	relatesTo, relationType := database.GetRelatesToFromBytes(mainContent)
	dbEvt := &database.Event{
		RoomID:          roomID,
		ID:              id.EventID(fmt.Sprintf("~%s", txnID)),
		Sender:          h.Account.UserID,
		Type:            evtType.Type,
		Timestamp:       time.Now(),
		Content:         mainContent,
		Decrypted:       decryptedContent,
		DecryptedType:   decryptedType.Type,
		Unsigned:        []byte("{}"),
		TransactionID:   txnID,
		RelatesTo:       relatesTo,
		RelationType:    relationType,
		MegolmSessionID: megolmSessionID,
		DecryptionError: "",
		SendError:       "not sent",
		Reactions:       map[string]int{},
		LastEditRowID:   &zero,
	}
	_, err = h.DB.Event.Insert(ctx, dbEvt)
	if err != nil {
		return nil, fmt.Errorf("failed to insert event into database: %w", err)
	}
	go func() {
		var err error
		defer func() {
			h.EventHandler(&SendComplete{
				Event: dbEvt,
				Error: err,
			})
		}()
		var resp *mautrix.RespSendEvent
		resp, err = h.Client.SendMessageEvent(ctx, roomID, evtType, content, mautrix.ReqSendEvent{
			Timestamp:     dbEvt.Timestamp.UnixMilli(),
			TransactionID: txnID,
			DontEncrypt:   true,
		})
		if err != nil {
			dbEvt.SendError = err.Error()
			err = fmt.Errorf("failed to send event: %w", err)
			err2 := h.DB.Event.UpdateSendError(ctx, dbEvt.RowID, dbEvt.SendError)
			if err2 != nil {
				zerolog.Ctx(ctx).Err(err2).AnErr("send_error", err).
					Msg("Failed to update send error in database after sending failed")
			}
			return
		}
		dbEvt.ID = resp.EventID
		err = h.DB.Event.UpdateID(ctx, dbEvt.RowID, dbEvt.ID)
		if err != nil {
			err = fmt.Errorf("failed to update event ID in database: %w", err)
		}
	}()
	return dbEvt, nil
}

func (h *HiClient) Encrypt(ctx context.Context, room *database.Room, evtType event.Type, content any) (encrypted *event.EncryptedEventContent, err error) {
	h.encryptLock.Lock()
	defer h.encryptLock.Unlock()
	encrypted, err = h.Crypto.EncryptMegolmEvent(ctx, room.ID, evtType, content)
	if errors.Is(err, crypto.SessionExpired) || errors.Is(err, crypto.NoGroupSession) || errors.Is(err, crypto.SessionNotShared) {
		if err = h.shareGroupSession(ctx, room); err != nil {
			err = fmt.Errorf("failed to share group session: %w", err)
		} else if encrypted, err = h.Crypto.EncryptMegolmEvent(ctx, room.ID, evtType, content); err != nil {
			err = fmt.Errorf("failed to encrypt event after re-sharing group session: %w", err)
		}
	}
	return
}

func (h *HiClient) EnsureGroupSessionShared(ctx context.Context, roomID id.RoomID) error {
	h.encryptLock.Lock()
	defer h.encryptLock.Unlock()
	if session, err := h.CryptoStore.GetOutboundGroupSession(ctx, roomID); err != nil {
		return fmt.Errorf("failed to get previous outbound group session: %w", err)
	} else if session != nil && session.Shared && !session.Expired() {
		return nil
	} else if roomMeta, err := h.DB.Room.Get(ctx, roomID); err != nil {
		return fmt.Errorf("failed to get room metadata: %w", err)
	} else if roomMeta == nil {
		return fmt.Errorf("unknown room")
	} else {
		return h.shareGroupSession(ctx, roomMeta)
	}
}

func (h *HiClient) loadMembers(ctx context.Context, room *database.Room) error {
	if room.HasMemberList {
		return nil
	}
	resp, err := h.Client.Members(ctx, room.ID)
	if err != nil {
		return fmt.Errorf("failed to get room member list: %w", err)
	}
	err = h.DB.DoTxn(ctx, nil, func(ctx context.Context) error {
		for _, evt := range resp.Chunk {
			dbEvt, err := h.processEvent(ctx, evt, nil, true)
			if err != nil {
				return err
			}
			membership := event.Membership(evt.Content.Raw["membership"].(string))
			err = h.DB.CurrentState.Set(ctx, room.ID, evt.Type, *evt.StateKey, dbEvt.RowID, membership)
			if err != nil {
				return err
			}
		}
		return h.DB.Room.Upsert(ctx, &database.Room{
			ID:            room.ID,
			HasMemberList: true,
		})
	})
	if err != nil {
		return fmt.Errorf("failed to process room member list: %w", err)
	}
	return nil
}

func (h *HiClient) shareGroupSession(ctx context.Context, room *database.Room) error {
	err := h.loadMembers(ctx, room)
	if err != nil {
		return err
	}
	shareToInvited := h.shouldShareKeysToInvitedUsers(ctx, room.ID)
	var users []id.UserID
	if shareToInvited {
		users, err = h.ClientStore.GetRoomJoinedOrInvitedMembers(ctx, room.ID)
	} else {
		users, err = h.ClientStore.GetRoomJoinedMembers(ctx, room.ID)
	}
	if err != nil {
		return fmt.Errorf("failed to get room member list: %w", err)
	} else if err = h.Crypto.ShareGroupSession(ctx, room.ID, users); err != nil {
		return fmt.Errorf("failed to share group session: %w", err)
	}
	return nil
}

func (h *HiClient) shouldShareKeysToInvitedUsers(ctx context.Context, roomID id.RoomID) bool {
	historyVisibility, err := h.DB.CurrentState.Get(ctx, roomID, event.StateHistoryVisibility, "")
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to get history visibility event")
		return false
	}
	mautrixEvt := historyVisibility.AsRawMautrix()
	err = mautrixEvt.Content.ParseRaw(mautrixEvt.Type)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to parse history visibility event")
		return false
	}
	hv, ok := mautrixEvt.Content.Parsed.(*event.HistoryVisibilityEventContent)
	if !ok {
		zerolog.Ctx(ctx).Warn().Msg("Unexpected parsed content type for history visibility event")
		return false
	}
	return hv.HistoryVisibility == event.HistoryVisibilityInvited ||
		hv.HistoryVisibility == event.HistoryVisibilityShared ||
		hv.HistoryVisibility == event.HistoryVisibilityWorldReadable
}
