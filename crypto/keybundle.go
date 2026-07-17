// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/ptr"

	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type RoomKeyBundle struct {
	RoomKeys []*ExportedSession                   `json:"room_keys,omitempty"`
	Withheld []*event.RoomKeyWithheldEventContent `json:"withheld,omitempty"`
}

func (mach *OlmMachine) receiveRoomKeyBundle(ctx context.Context, evt *DecryptedOlmEvent, content *event.RoomKeyBundleEventContent) {
	if evt.SenderDeviceKeys == nil {
		zerolog.Ctx(ctx).Warn().
			Stringer("room_id", content.RoomID).
			Msg("Dropping room key bundle with no sender device keys")
		return
	}
	if mach.OnRoomKeyBundle != nil {
		mach.OnRoomKeyBundle(ctx, content)
	} else {
		zerolog.Ctx(ctx).Debug().
			Stringer("room_id", content.RoomID).
			Msg("No room key bundle handler set")
	}
}

func (mach *OlmMachine) DownloadRoomKeyBundle(ctx context.Context, content *event.RoomKeyBundleEventContent) (*RoomKeyBundle, error) {
	parsedURL, err := content.File.URL.Parse()
	if err != nil {
		return nil, fmt.Errorf("failed to parse file URL: %w", err)
	}
	err = content.File.PrepareForDecryption()
	if err != nil {
		return nil, fmt.Errorf("failed to parse file keys: %w", err)
	}
	resp, err := mach.Client.Download(ctx, parsedURL)
	if err != nil {
		return nil, fmt.Errorf("failed to download file: %w", err)
	}
	var bundle RoomKeyBundle
	stream := content.File.DecryptStream(resp.Body)
	err = json.NewDecoder(stream).Decode(&bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to decode room key bundle: %w", err)
	}
	err = stream.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close decryption stream: %w", err)
	}
	return &bundle, nil
}

var (
	ErrKeyBundleUnknownAlgorithm     = errors.New("ignoring room key in bundle with weird algorithm")
	ErrKeyBundleMismatchingRoomID    = errors.New("mismatching room ID in key bundle session")
	ErrKeyBundleMismatchingSessionID = errors.New("imported session from key bundle has different ID than expected")
)

func (mach *OlmMachine) ImportRoomKeyFromBundleWithoutSaving(
	session *ExportedSession,
	evt *DecryptedOlmEvent,
	config *event.EncryptionEventContent,
) (*InboundGroupSession, error) {
	bundleContent, ok := evt.Content.Parsed.(*event.RoomKeyBundleEventContent)
	if !ok {
		return nil, fmt.Errorf("invalid room key bundle event content type: %T", evt.Content.Parsed)
	}
	roomID := bundleContent.RoomID
	if session.Algorithm != id.AlgorithmMegolmV1 {
		return nil, fmt.Errorf("%w %s", ErrKeyBundleUnknownAlgorithm, session.Algorithm)
	} else if session.RoomID != roomID {
		return nil, fmt.Errorf("%w (%q != %q)", ErrKeyBundleMismatchingRoomID, session.RoomID, roomID)
	}

	igsInternal, err := olm.InboundGroupSessionImport([]byte(session.SessionKey))
	if err != nil {
		return nil, fmt.Errorf("failed to import session from bundle: %w", err)
	} else if igsInternal.ID() != session.SessionID {
		return nil, fmt.Errorf("%w (%q != %q)", ErrKeyBundleMismatchingSessionID, session.SessionID, igsInternal.ID())
	}
	var maxAge time.Duration
	var maxMessages int
	if config != nil {
		maxAge = time.Duration(config.RotationPeriodMillis) * time.Millisecond
		maxMessages = config.RotationPeriodMessages
	}
	return &InboundGroupSession{
		Internal:         igsInternal,
		SigningKey:       session.SenderClaimedKeys.Ed25519,
		SenderKey:        session.SenderKey,
		RoomID:           session.RoomID,
		ForwardingChains: []string{evt.SenderKey.String()},
		id:               session.SessionID,

		ReceivedAt:    time.Now().UTC(),
		MaxAge:        maxAge.Milliseconds(),
		MaxMessages:   maxMessages,
		SharedHistory: ptr.Ptr(true),
		KeySource:     id.KeySourceForward,
	}, nil
}

func (mach *OlmMachine) ImportRoomKeyFromBundle(
	ctx context.Context,
	evt *DecryptedOlmEvent,
	session *ExportedSession,
) (*InboundGroupSession, error) {
	config, err := mach.StateStore.GetEncryptionEvent(ctx, session.RoomID)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Stringer("room_id", session.RoomID).
			Stringer("session_id", session.SessionID).
			Msg("Failed to get encryption event for room")
	}
	imported, err := mach.ImportRoomKeyFromBundleWithoutSaving(session, evt, config)
	if err != nil {
		return nil, err
	}
	err = mach.StoreGroupSession(ctx, imported, true)
	if err != nil {
		return nil, fmt.Errorf("failed to store room key from bundle: %w", err)
	}
	return imported, nil
}

func (mach *OlmMachine) ImportRoomKeyBundle(ctx context.Context, evt *DecryptedOlmEvent, bundle *RoomKeyBundle) {
	for _, withheld := range bundle.Withheld {
		mach.HandleRoomKeyWithheld(ctx, withheld)
	}
	for _, sess := range bundle.RoomKeys {
		_, err := mach.ImportRoomKeyFromBundle(ctx, evt, sess)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Stringer("session_id", sess.SessionID).
				Msg("Failed to import key from bundle")
		}
	}
}
