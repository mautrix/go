// Copyright (c) 2024 Tulir Asokan
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

	"github.com/rs/zerolog"

	"github.com/element-hq/mautrix-go/crypto/olm"
	"github.com/element-hq/mautrix-go/event"
	"github.com/element-hq/mautrix-go/id"
)

var (
	IncorrectEncryptedContentType = errors.New("event content is not instance of *event.EncryptedEventContent")
	NoSessionFound                = errors.New("failed to decrypt megolm event: no session with given ID found")
	DuplicateMessageIndex         = errors.New("duplicate megolm message index")
	WrongRoom                     = errors.New("encrypted megolm event is not intended for this room")
	DeviceKeyMismatch             = errors.New("device keys in event and verified device info do not match")
	SenderKeyMismatch             = errors.New("sender keys in content and megolm session do not match")
	RatchetError                  = errors.New("failed to ratchet session after use")
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
	sess, plaintext, messageIndex, err := mach.actuallyDecryptMegolmEvent(ctx, evt, encryptionRoomID, content)
	if err != nil {
		return nil, err
	}
	log = log.With().Uint("message_index", messageIndex).Logger()

	var trustLevel id.TrustState
	var forwardedKeys bool
	var device *id.Device
	ownSigningKey, ownIdentityKey := mach.account.Keys()
	if sess.SigningKey == ownSigningKey && sess.SenderKey == ownIdentityKey && len(sess.ForwardingChains) == 0 {
		trustLevel = id.TrustStateVerified
	} else {
		if mach.DisableDecryptKeyFetching {
			device, err = mach.CryptoStore.FindDeviceByKey(ctx, evt.Sender, sess.SenderKey)
		} else {
			device, err = mach.GetOrFetchDeviceByKey(ctx, evt.Sender, sess.SenderKey)
		}
		if err != nil {
			// We don't want to throw these errors as the message can still be decrypted.
			log.Debug().Err(err).Msg("Failed to get device to verify session")
			trustLevel = id.TrustStateUnknownDevice
		} else if len(sess.ForwardingChains) == 0 || (len(sess.ForwardingChains) == 1 && sess.ForwardingChains[0] == sess.SenderKey.String()) {
			if device == nil {
				log.Debug().
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
			device, _ = mach.CryptoStore.FindDeviceByKey(ctx, evt.Sender, id.IdentityKey(lastChainItem))
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

func removeItem(slice []uint, item uint) ([]uint, bool) {
	for i, s := range slice {
		if s == item {
			return append(slice[:i], slice[i+1:]...), true
		}
	}
	return slice, false
}

const missedIndexCutoff = 10

func (mach *OlmMachine) checkUndecryptableMessageIndexDuplication(ctx context.Context, sess *InboundGroupSession, evt *event.Event, content *event.EncryptedEventContent) (uint, error) {
	log := *zerolog.Ctx(ctx)
	messageIndex, decodeErr := parseMessageIndex(content.MegolmCiphertext)
	if decodeErr != nil {
		log.Warn().Err(decodeErr).Msg("Failed to parse message index to check if it's a duplicate for message that failed to decrypt")
		return 0, fmt.Errorf("%w (also failed to parse message index)", olm.UnknownMessageIndex)
	}
	firstKnown := sess.Internal.FirstKnownIndex()
	log = log.With().Uint("message_index", messageIndex).Uint32("first_known_index", firstKnown).Logger()
	if ok, err := mach.CryptoStore.ValidateMessageIndex(ctx, sess.SenderKey, content.SessionID, evt.ID, messageIndex, evt.Timestamp); err != nil {
		log.Debug().Err(err).Msg("Failed to check if message index is duplicate")
		return messageIndex, fmt.Errorf("%w (failed to check if index is duplicate; received: %d, earliest known: %d)", olm.UnknownMessageIndex, messageIndex, firstKnown)
	} else if !ok {
		log.Debug().Msg("Failed to decrypt message due to unknown index and found duplicate")
		return messageIndex, fmt.Errorf("%w %d (also failed to decrypt because earliest known index is %d)", DuplicateMessageIndex, messageIndex, firstKnown)
	}
	log.Debug().Msg("Failed to decrypt message due to unknown index, but index is not duplicate")
	return messageIndex, fmt.Errorf("%w (not duplicate index; received: %d, earliest known: %d)", olm.UnknownMessageIndex, messageIndex, firstKnown)
}

func (mach *OlmMachine) actuallyDecryptMegolmEvent(ctx context.Context, evt *event.Event, encryptionRoomID id.RoomID, content *event.EncryptedEventContent) (*InboundGroupSession, []byte, uint, error) {
	mach.megolmDecryptLock.Lock()
	defer mach.megolmDecryptLock.Unlock()

	sess, err := mach.CryptoStore.GetGroupSession(ctx, encryptionRoomID, content.SenderKey, content.SessionID)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to get group session: %w", err)
	} else if sess == nil {
		return nil, nil, 0, fmt.Errorf("%w (ID %s)", NoSessionFound, content.SessionID)
	} else if content.SenderKey != "" && content.SenderKey != sess.SenderKey {
		return sess, nil, 0, SenderKeyMismatch
	}
	plaintext, messageIndex, err := sess.Internal.Decrypt(content.MegolmCiphertext)
	if err != nil {
		if errors.Is(err, olm.UnknownMessageIndex) && mach.RatchetKeysOnDecrypt {
			messageIndex, err = mach.checkUndecryptableMessageIndexDuplication(ctx, sess, evt, content)
			return sess, nil, messageIndex, fmt.Errorf("failed to decrypt megolm event: %w", err)
		}
		return sess, nil, 0, fmt.Errorf("failed to decrypt megolm event: %w", err)
	} else if ok, err := mach.CryptoStore.ValidateMessageIndex(ctx, sess.SenderKey, content.SessionID, evt.ID, messageIndex, evt.Timestamp); err != nil {
		return sess, nil, messageIndex, fmt.Errorf("failed to check if message index is duplicate: %w", err)
	} else if !ok {
		return sess, nil, messageIndex, fmt.Errorf("%w %d", DuplicateMessageIndex, messageIndex)
	}

	expectedMessageIndex := sess.RatchetSafety.NextIndex
	didModify := false
	switch {
	case messageIndex > expectedMessageIndex:
		// When the index jumps, add indices in between to the missed indices list.
		for i := expectedMessageIndex; i < messageIndex; i++ {
			sess.RatchetSafety.MissedIndices = append(sess.RatchetSafety.MissedIndices, i)
		}
		fallthrough
	case messageIndex == expectedMessageIndex:
		// When the index moves forward (to the next one or jumping ahead), update the last received index.
		sess.RatchetSafety.NextIndex = messageIndex + 1
		didModify = true
	default:
		sess.RatchetSafety.MissedIndices, didModify = removeItem(sess.RatchetSafety.MissedIndices, messageIndex)
	}
	// Use presence of ReceivedAt as a sign that this is a recent megolm session,
	// and therefore it's safe to drop missed indices entirely.
	if !sess.ReceivedAt.IsZero() && len(sess.RatchetSafety.MissedIndices) > 0 && int(sess.RatchetSafety.MissedIndices[0]) < int(sess.RatchetSafety.NextIndex)-missedIndexCutoff {
		limit := sess.RatchetSafety.NextIndex - missedIndexCutoff
		var cutoff int
		for ; cutoff < len(sess.RatchetSafety.MissedIndices) && sess.RatchetSafety.MissedIndices[cutoff] < limit; cutoff++ {
		}
		sess.RatchetSafety.LostIndices = append(sess.RatchetSafety.LostIndices, sess.RatchetSafety.MissedIndices[:cutoff]...)
		sess.RatchetSafety.MissedIndices = sess.RatchetSafety.MissedIndices[cutoff:]
		didModify = true
	}
	ratchetTargetIndex := uint32(sess.RatchetSafety.NextIndex)
	if len(sess.RatchetSafety.MissedIndices) > 0 {
		ratchetTargetIndex = uint32(sess.RatchetSafety.MissedIndices[0])
	}
	ratchetCurrentIndex := sess.Internal.FirstKnownIndex()
	log := zerolog.Ctx(ctx).With().
		Uint32("prev_ratchet_index", ratchetCurrentIndex).
		Uint32("new_ratchet_index", ratchetTargetIndex).
		Uint("next_new_index", sess.RatchetSafety.NextIndex).
		Uints("missed_indices", sess.RatchetSafety.MissedIndices).
		Uints("lost_indices", sess.RatchetSafety.LostIndices).
		Int("max_messages", sess.MaxMessages).
		Logger()
	if sess.MaxMessages > 0 && int(ratchetTargetIndex) >= sess.MaxMessages && len(sess.RatchetSafety.MissedIndices) == 0 && mach.DeleteFullyUsedKeysOnDecrypt {
		err = mach.CryptoStore.RedactGroupSession(ctx, sess.RoomID, sess.SenderKey, sess.ID(), "maximum messages reached")
		if err != nil {
			log.Err(err).Msg("Failed to delete fully used session")
			return sess, plaintext, messageIndex, RatchetError
		} else {
			log.Info().Msg("Deleted fully used session")
		}
	} else if ratchetCurrentIndex < ratchetTargetIndex && mach.RatchetKeysOnDecrypt {
		if err = sess.RatchetTo(ratchetTargetIndex); err != nil {
			log.Err(err).Msg("Failed to ratchet session")
			return sess, plaintext, messageIndex, RatchetError
		} else if err = mach.CryptoStore.PutGroupSession(ctx, sess.RoomID, sess.SenderKey, sess.ID(), sess); err != nil {
			log.Err(err).Msg("Failed to store ratcheted session")
			return sess, plaintext, messageIndex, RatchetError
		} else {
			log.Info().Msg("Ratcheted session forward")
		}
	} else if didModify {
		if err = mach.CryptoStore.PutGroupSession(ctx, sess.RoomID, sess.SenderKey, sess.ID(), sess); err != nil {
			log.Err(err).Msg("Failed to store updated ratchet safety data")
			return sess, plaintext, messageIndex, RatchetError
		} else {
			log.Debug().Msg("Ratchet safety data changed (ratchet state didn't change)")
		}
	} else {
		log.Debug().Msg("Ratchet safety data didn't change")
	}
	return sess, plaintext, messageIndex, nil
}
