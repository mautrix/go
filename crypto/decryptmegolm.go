// Copyright (c) 2023 Tulir Asokan
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
	"strings"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

var (
	IncorrectEncryptedContentType = errors.New("event content is not instance of *event.EncryptedEventContent")
	NoSessionFound                = errors.New("failed to decrypt megolm event: no session with given ID found")
	DuplicateMessageIndex         = errors.New("duplicate megolm message index")
	WrongRoom                     = errors.New("encrypted megolm event is not intended for this room")
	DeviceKeyMismatch             = errors.New("device keys in event and verified device info do not match")
	SenderKeyMismatch             = errors.New("sender keys in content and megolm session do not match")
)

type megolmEvent struct {
	RoomID  id.RoomID     `json:"room_id"`
	Type    event.Type    `json:"type"`
	Content event.Content `json:"content"`
}

// DecryptMegolmEvent decrypts an m.room.encrypted event where the algorithm is m.megolm.v1.aes-sha2
func (mach *OlmMachine) DecryptMegolmEvent(ctx context.Context, evt *event.Event) (*event.Event, error) {
	content, ok := evt.Content.Parsed.(*event.EncryptedEventContent)
	if !ok {
		return nil, IncorrectEncryptedContentType
	} else if content.Algorithm != id.AlgorithmMegolmV1 {
		return nil, UnsupportedAlgorithm
	}
	log := mach.machOrContextLog(ctx).With().
		Str("action", "decrypt megolm event").
		Str("event_id", evt.ID.String()).
		Str("sender", evt.Sender.String()).
		Str("sender_key", content.SenderKey.String()).
		Str("session_id", content.SessionID.String()).
		Logger()
	ctx = log.WithContext(ctx)
	encryptionRoomID := evt.RoomID
	// Allow the server to move encrypted events between rooms if both the real room and target room are on a non-federatable .local domain.
	// The message index checks to prevent replay attacks still apply and aren't based on the room ID,
	// so the event ID and timestamp must remain the same when the event is moved to a different room.
	if origRoomID, ok := evt.Content.Raw["com.beeper.original_room_id"].(string); ok && strings.HasSuffix(origRoomID, ".local") && strings.HasSuffix(evt.RoomID.String(), ".local") {
		encryptionRoomID = id.RoomID(origRoomID)
	}
	sess, err := mach.CryptoStore.GetGroupSession(encryptionRoomID, content.SenderKey, content.SessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get group session: %w", err)
	} else if sess == nil {
		return nil, fmt.Errorf("%w (ID %s)", NoSessionFound, content.SessionID)
	} else if content.SenderKey != "" && content.SenderKey != sess.SenderKey {
		return nil, SenderKeyMismatch
	}
	plaintext, messageIndex, err := sess.Internal.Decrypt(content.MegolmCiphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt megolm event: %w", err)
	} else if ok, err = mach.CryptoStore.ValidateMessageIndex(ctx, sess.SenderKey, content.SessionID, evt.ID, messageIndex, evt.Timestamp); err != nil {
		return nil, fmt.Errorf("failed to check if message index is duplicate: %w", err)
	} else if !ok {
		return nil, DuplicateMessageIndex
	}
	log = log.With().Uint("message_index", messageIndex).Logger()

	var trustLevel id.TrustState
	var forwardedKeys bool
	var device *id.Device
	ownSigningKey, ownIdentityKey := mach.account.Keys()
	if sess.SigningKey == ownSigningKey && sess.SenderKey == ownIdentityKey && len(sess.ForwardingChains) == 0 {
		trustLevel = id.TrustStateVerified
	} else {
		device, err = mach.GetOrFetchDeviceByKey(ctx, evt.Sender, sess.SenderKey)
		if err != nil {
			// We don't want to throw these errors as the message can still be decrypted.
			log.Debug().Err(err).Msg("Failed to get device to verify session")
			trustLevel = id.TrustStateUnknownDevice
		} else if len(sess.ForwardingChains) == 0 || (len(sess.ForwardingChains) == 1 && sess.ForwardingChains[0] == sess.SenderKey.String()) {
			if device == nil {
				log.Debug().Err(err).
					Str("session_sender_key", sess.SenderKey.String()).
					Msg("Couldn't resolve trust level of session: sent by unknown device")
				trustLevel = id.TrustStateUnknownDevice
			} else if device.SigningKey != sess.SigningKey || device.IdentityKey != sess.SenderKey {
				return nil, DeviceKeyMismatch
			} else {
				trustLevel = mach.ResolveTrust(device)
			}
		} else {
			forwardedKeys = true
			lastChainItem := sess.ForwardingChains[len(sess.ForwardingChains)-1]
			device, _ = mach.CryptoStore.FindDeviceByKey(evt.Sender, id.IdentityKey(lastChainItem))
			if device != nil {
				trustLevel = mach.ResolveTrust(device)
			} else {
				log.Debug().
					Str("forward_last_sender_key", lastChainItem).
					Msg("Couldn't resolve trust level of session: forwarding chain ends with unknown device")
				trustLevel = id.TrustStateForwarded
			}
		}
	}

	megolmEvt := &megolmEvent{}
	err = json.Unmarshal(plaintext, &megolmEvt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse megolm payload: %w", err)
	} else if megolmEvt.RoomID != encryptionRoomID {
		return nil, WrongRoom
	}
	megolmEvt.Type.Class = evt.Type.Class
	log = log.With().Str("decrypted_event_type", megolmEvt.Type.Repr()).Logger()
	err = megolmEvt.Content.ParseRaw(megolmEvt.Type)
	if err != nil {
		if errors.Is(err, event.ErrUnsupportedContentType) {
			log.Warn().Msg("Unsupported event type in encrypted event")
		} else {
			return nil, fmt.Errorf("failed to parse content of megolm payload event: %w", err)
		}
	}
	if content.RelatesTo != nil {
		relatable, ok := megolmEvt.Content.Parsed.(event.Relatable)
		if ok {
			if relatable.OptionalGetRelatesTo() == nil {
				relatable.SetRelatesTo(content.RelatesTo)
			} else {
				log.Trace().Msg("Not overriding relation data as encrypted payload already has it")
			}
		}
		if _, hasRelation := megolmEvt.Content.Raw["m.relates_to"]; !hasRelation {
			megolmEvt.Content.Raw["m.relates_to"] = evt.Content.Raw["m.relates_to"]
		}
	}
	log.Debug().Msg("Event decrypted successfully")
	megolmEvt.Type.Class = evt.Type.Class
	return &event.Event{
		Sender:    evt.Sender,
		Type:      megolmEvt.Type,
		Timestamp: evt.Timestamp,
		ID:        evt.ID,
		RoomID:    evt.RoomID,
		Content:   megolmEvt.Content,
		Unsigned:  evt.Unsigned,
		Mautrix: event.MautrixInfo{
			TrustState:    trustLevel,
			TrustSource:   device,
			ForwardedKeys: forwardedKeys,
			WasEncrypted:  true,
			ReceivedAt:    evt.Mautrix.ReceivedAt,
		},
	}, nil
}
