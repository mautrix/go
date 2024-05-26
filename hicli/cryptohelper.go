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
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type hiCryptoHelper HiClient

var _ mautrix.CryptoHelper = (*hiCryptoHelper)(nil)

func (h *hiCryptoHelper) Encrypt(ctx context.Context, roomID id.RoomID, evtType event.Type, content any) (encrypted *event.EncryptedEventContent, err error) {
	h.encryptLock.Lock()
	defer h.encryptLock.Unlock()
	encrypted, err = h.Crypto.EncryptMegolmEvent(ctx, roomID, evtType, content)
	if err != nil {
		if !errors.Is(err, crypto.SessionExpired) && !errors.Is(err, crypto.NoGroupSession) && !errors.Is(err, crypto.SessionNotShared) {
			return
		}
		h.Log.Debug().
			Err(err).
			Str("room_id", roomID.String()).
			Msg("Got session error while encrypting event, sharing group session and trying again")
		var users []id.UserID
		users, err = h.ClientStore.GetRoomJoinedOrInvitedMembers(ctx, roomID)
		if err != nil {
			err = fmt.Errorf("failed to get room member list: %w", err)
		} else if err = h.Crypto.ShareGroupSession(ctx, roomID, users); err != nil {
			err = fmt.Errorf("failed to share group session: %w", err)
		} else if encrypted, err = h.Crypto.EncryptMegolmEvent(ctx, roomID, evtType, content); err != nil {
			err = fmt.Errorf("failed to encrypt event after re-sharing group session: %w", err)
		}
	}
	return
}

func (h *hiCryptoHelper) Decrypt(ctx context.Context, evt *event.Event) (*event.Event, error) {
	return h.Crypto.DecryptMegolmEvent(ctx, evt)
}

func (h *hiCryptoHelper) WaitForSession(ctx context.Context, roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID, timeout time.Duration) bool {
	return h.Crypto.WaitForSession(ctx, roomID, senderKey, sessionID, timeout)
}

func (h *hiCryptoHelper) RequestSession(ctx context.Context, roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID, userID id.UserID, deviceID id.DeviceID) {
	err := h.Crypto.SendRoomKeyRequest(ctx, roomID, senderKey, sessionID, "", map[id.UserID][]id.DeviceID{
		userID:           {deviceID},
		h.Account.UserID: {"*"},
	})
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Stringer("room_id", roomID).
			Stringer("session_id", sessionID).
			Stringer("user_id", userID).
			Msg("Failed to send room key request")
	} else {
		zerolog.Ctx(ctx).Debug().
			Stringer("room_id", roomID).
			Stringer("session_id", sessionID).
			Stringer("user_id", userID).
			Msg("Sent room key request")
	}
}

func (h *hiCryptoHelper) Init(ctx context.Context) error {
	return nil
}
