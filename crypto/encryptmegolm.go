// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/rs/zerolog"
	"github.com/tidwall/gjson"
	"go.mau.fi/util/exgjson"
	"go.mau.fi/util/exzerolog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

var (
	AlreadyShared  = errors.New("group session already shared")
	NoGroupSession = errors.New("no group session created")
)

func getRawJSON[T any](content json.RawMessage, path ...string) *T {
	value := gjson.GetBytes(content, exgjson.Path(path...))
	if !value.IsObject() {
		return nil
	}
	var result T
	err := json.Unmarshal([]byte(value.Raw), &result)
	if err != nil {
		return nil
	}
	return &result
}

func getRelatesTo(content any) *event.RelatesTo {
	contentJSON, ok := content.(json.RawMessage)
	if ok {
		return getRawJSON[event.RelatesTo](contentJSON, "m.relates_to")
	}
	contentStruct, ok := content.(*event.Content)
	if ok {
		content = contentStruct.Parsed
	}
	relatable, ok := content.(event.Relatable)
	if ok {
		return relatable.OptionalGetRelatesTo()
	}
	return nil
}

func getMentions(content any) *event.Mentions {
	contentJSON, ok := content.(json.RawMessage)
	if ok {
		return getRawJSON[event.Mentions](contentJSON, "m.mentions")
	}
	contentStruct, ok := content.(*event.Content)
	if ok {
		content = contentStruct.Parsed
	}
	message, ok := content.(*event.MessageEventContent)
	if ok {
		return message.Mentions
	}
	return nil
}

type rawMegolmEvent struct {
	RoomID   id.RoomID   `json:"room_id"`
	Type     event.Type  `json:"type"`
	StateKey *string     `json:"state_key,omitempty"`
	Content  interface{} `json:"content"`
}

// IsShareError returns true if the error is caused by the lack of an outgoing megolm session and can be solved with OlmMachine.ShareGroupSession
func IsShareError(err error) bool {
	return err == SessionExpired || err == SessionNotShared || err == NoGroupSession
}

func ParseMegolmMessageIndex(ciphertext []byte) (uint, error) {
	decoded := make([]byte, base64.RawStdEncoding.DecodedLen(len(ciphertext)))
	var err error
	_, err = base64.RawStdEncoding.Decode(decoded, ciphertext)
	if err != nil {
		return 0, err
	} else if decoded[0] != 3 || decoded[1] != 8 {
		return 0, fmt.Errorf("unexpected initial bytes %d and %d", decoded[0], decoded[1])
	}
	index, read := binary.Uvarint(decoded[2 : 2+binary.MaxVarintLen64])
	if read <= 0 {
		return 0, fmt.Errorf("failed to decode varint, read value %d", read)
	}
	return uint(index), nil
}

// EncryptMegolmEvent encrypts data with the m.megolm.v1.aes-sha2 algorithm.
//
// If you use the event.Content struct, make sure you pass a pointer to the struct,
// as JSON serialization will not work correctly otherwise.
func (mach *OlmMachine) EncryptMegolmEvent(ctx context.Context, roomID id.RoomID, evtType event.Type, content interface{}) (*event.EncryptedEventContent, error) {
	return mach.EncryptMegolmEventWithStateKey(ctx, roomID, evtType, nil, content)
}

// EncryptMegolmEventWithStateKey encrypts data with the m.megolm.v1.aes-sha2 algorithm.
//
// If you use the event.Content struct, make sure you pass a pointer to the struct,
// as JSON serialization will not work correctly otherwise.
func (mach *OlmMachine) EncryptMegolmEventWithStateKey(ctx context.Context, roomID id.RoomID, evtType event.Type, stateKey *string, content interface{}) (*event.EncryptedEventContent, error) {
	mach.megolmEncryptLock.Lock()
	defer mach.megolmEncryptLock.Unlock()
	session, err := mach.CryptoStore.GetOutboundGroupSession(ctx, roomID)
	if err != nil {
		return nil, fmt.Errorf("failed to get outbound group session: %w", err)
	} else if session == nil {
		return nil, NoGroupSession
	}
	plaintext, err := json.Marshal(&rawMegolmEvent{
		RoomID:   roomID,
		Type:     evtType,
		StateKey: stateKey,
		Content:  content,
	})
	if err != nil {
		return nil, err
	}
	log := mach.machOrContextLog(ctx).With().
		Str("event_type", evtType.Type).
		Any("state_key", stateKey).
		Str("room_id", roomID.String()).
		Str("session_id", session.ID().String()).
		Uint("expected_index", session.Internal.MessageIndex()).
		Logger()
	log.Trace().Msg("Encrypting event...")
	ciphertext, err := session.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	idx, err := ParseMegolmMessageIndex(ciphertext)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get megolm message index of encrypted event")
	} else {
		log = log.With().Uint("message_index", idx).Logger()
	}
	log.Debug().Msg("Encrypted event successfully")
	err = mach.CryptoStore.UpdateOutboundGroupSession(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("failed to update outbound group session after encrypting: %w", err)
	}
	encrypted := &event.EncryptedEventContent{
		Algorithm:        id.AlgorithmMegolmV1,
		SessionID:        session.ID(),
		MegolmCiphertext: ciphertext,
		RelatesTo:        getRelatesTo(content),

		// These are deprecated
		SenderKey: mach.account.IdentityKey(),
		DeviceID:  mach.Client.DeviceID,
	}
	if mach.PlaintextMentions {
		encrypted.Mentions = getMentions(content)
	}
	return encrypted, nil
}

func (mach *OlmMachine) newOutboundGroupSession(ctx context.Context, roomID id.RoomID) (*OutboundGroupSession, error) {
	encryptionEvent, err := mach.StateStore.GetEncryptionEvent(ctx, roomID)
	if err != nil {
		mach.machOrContextLog(ctx).Err(err).
			Stringer("room_id", roomID).
			Msg("Failed to get encryption event in room")
		return nil, fmt.Errorf("failed to get encryption event in room %s: %w", roomID, err)
	}
	session, err := NewOutboundGroupSession(roomID, encryptionEvent)
	if err != nil {
		return nil, err
	}
	if !mach.DontStoreOutboundKeys {
		signingKey, idKey := mach.account.Keys()
		err := mach.createGroupSession(ctx, idKey, signingKey, roomID, session.ID(), session.Internal.Key(), session.MaxAge, session.MaxMessages, false)
		if err != nil {
			return nil, err
		}
	}
	return session, err
}

type deviceSessionWrapper struct {
	session  *OlmSession
	identity *id.Device
}

// ShareGroupSession shares a group session for a specific room with all the devices of the given user list.
//
// For devices with TrustStateBlacklisted, a m.room_key.withheld event with code=m.blacklisted is sent.
// If AllowUnverifiedDevices is false, a similar event with code=m.unverified is sent to devices with TrustStateUnset
func (mach *OlmMachine) ShareGroupSession(ctx context.Context, roomID id.RoomID, users []id.UserID) error {
	mach.megolmEncryptLock.Lock()
	defer mach.megolmEncryptLock.Unlock()
	session, err := mach.CryptoStore.GetOutboundGroupSession(ctx, roomID)
	if err != nil {
		return fmt.Errorf("failed to get previous outbound group session: %w", err)
	} else if session != nil && session.Shared && !session.Expired() {
		return AlreadyShared
	}
	log := mach.machOrContextLog(ctx).With().
		Str("room_id", roomID.String()).
		Str("action", "share megolm session").
		Logger()
	ctx = log.WithContext(ctx)
	if session == nil || session.Expired() {
		if session, err = mach.newOutboundGroupSession(ctx, roomID); err != nil {
			return err
		}
	}
	log = log.With().Str("session_id", session.ID().String()).Logger()
	ctx = log.WithContext(ctx)
	log.Debug().Array("users", exzerolog.ArrayOfStrs(users)).Msg("Sharing group session for room")

	withheldCount := 0
	toDeviceWithheld := &mautrix.ReqSendToDevice{Messages: make(map[id.UserID]map[id.DeviceID]*event.Content)}
	olmSessions := make(map[id.UserID]map[id.DeviceID]deviceSessionWrapper)
	missingSessions := make(map[id.UserID]map[id.DeviceID]*id.Device)
	missingUserSessions := make(map[id.DeviceID]*id.Device)
	var fetchKeysForUsers []id.UserID

	for _, userID := range users {
		log := log.With().Str("target_user_id", userID.String()).Logger()
		devices, err := mach.CryptoStore.GetDevices(ctx, userID)
		if err != nil {
			log.Err(err).Msg("Failed to get devices of user")
			return fmt.Errorf("failed to get devices of user %s: %w", userID, err)
		} else if devices == nil {
			log.Debug().Msg("GetDevices returned nil, will fetch keys and retry")
			fetchKeysForUsers = append(fetchKeysForUsers, userID)
		} else if len(devices) == 0 {
			log.Trace().Msg("User has no devices, skipping")
		} else {
			log.Trace().Msg("Trying to find olm session to encrypt megolm session for user")
			toDeviceWithheld.Messages[userID] = make(map[id.DeviceID]*event.Content)
			olmSessions[userID] = make(map[id.DeviceID]deviceSessionWrapper)
			mach.findOlmSessionsForUser(ctx, session, userID, devices, olmSessions[userID], toDeviceWithheld.Messages[userID], missingUserSessions)
			log.Debug().
				Int("olm_session_count", len(olmSessions[userID])).
				Int("withheld_count", len(toDeviceWithheld.Messages[userID])).
				Int("missing_count", len(missingUserSessions)).
				Msg("Completed first pass of finding olm sessions")
			withheldCount += len(toDeviceWithheld.Messages[userID])
			if len(missingUserSessions) > 0 {
				missingSessions[userID] = missingUserSessions
				missingUserSessions = make(map[id.DeviceID]*id.Device)
			}
			if len(toDeviceWithheld.Messages[userID]) == 0 {
				delete(toDeviceWithheld.Messages, userID)
			}
		}
	}

	if len(fetchKeysForUsers) > 0 {
		log.Debug().Array("users", exzerolog.ArrayOfStrs(fetchKeysForUsers)).Msg("Fetching missing keys")
		keys, err := mach.FetchKeys(ctx, fetchKeysForUsers, true)
		if err != nil {
			log.Err(err).Array("users", exzerolog.ArrayOfStrs(fetchKeysForUsers)).Msg("Failed to fetch missing keys")
			return fmt.Errorf("failed to fetch missing keys: %w", err)
		}
		for userID, devices := range keys {
			log.Debug().
				Int("device_count", len(devices)).
				Str("target_user_id", userID.String()).
				Msg("Got device keys for user")
			missingSessions[userID] = devices
		}
	}

	if len(missingSessions) > 0 {
		log.Debug().Msg("Creating missing olm sessions")
		err = mach.createOutboundSessions(ctx, missingSessions)
		if err != nil {
			log.Err(err).Msg("Failed to create missing olm sessions")
			return fmt.Errorf("failed to create missing olm sessions: %w", err)
		}
	}

	for userID, devices := range missingSessions {
		if len(devices) == 0 {
			// No missing sessions
			continue
		}
		output, ok := olmSessions[userID]
		if !ok {
			output = make(map[id.DeviceID]deviceSessionWrapper)
			olmSessions[userID] = output
		}
		withheld, ok := toDeviceWithheld.Messages[userID]
		if !ok {
			withheld = make(map[id.DeviceID]*event.Content)
			toDeviceWithheld.Messages[userID] = withheld
		}

		log := log.With().Str("target_user_id", userID.String()).Logger()
		log.Trace().Msg("Trying to find olm session to encrypt megolm session for user (post-fetch retry)")
		mach.findOlmSessionsForUser(ctx, session, userID, devices, output, withheld, nil)
		log.Debug().
			Int("olm_session_count", len(output)).
			Int("withheld_count", len(withheld)).
			Msg("Completed post-fetch retry of finding olm sessions")
		withheldCount += len(toDeviceWithheld.Messages[userID])
		if len(toDeviceWithheld.Messages[userID]) == 0 {
			delete(toDeviceWithheld.Messages, userID)
		}
	}

	err = mach.encryptAndSendGroupSession(ctx, session, olmSessions)
	if err != nil {
		return fmt.Errorf("failed to share group session: %w", err)
	}

	if len(toDeviceWithheld.Messages) > 0 {
		log.Debug().
			Int("device_count", withheldCount).
			Int("user_count", len(toDeviceWithheld.Messages)).
			Msg("Sending to-device messages to report withheld key")
		// TODO remove the next 4 lines once clients support m.room_key.withheld
		_, err = mach.Client.SendToDevice(ctx, event.ToDeviceOrgMatrixRoomKeyWithheld, toDeviceWithheld)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to report withheld keys (legacy event type)")
		}
		_, err = mach.Client.SendToDevice(ctx, event.ToDeviceRoomKeyWithheld, toDeviceWithheld)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to report withheld keys")
		}
	}

	log.Debug().Msg("Group session successfully shared")
	session.Shared = true
	return mach.CryptoStore.AddOutboundGroupSession(ctx, session)
}

func (mach *OlmMachine) encryptAndSendGroupSession(ctx context.Context, session *OutboundGroupSession, olmSessions map[id.UserID]map[id.DeviceID]deviceSessionWrapper) error {
	mach.olmLock.Lock()
	defer mach.olmLock.Unlock()
	log := zerolog.Ctx(ctx)
	log.Trace().Msg("Encrypting group session for all found devices")
	deviceCount := 0
	toDevice := &mautrix.ReqSendToDevice{Messages: make(map[id.UserID]map[id.DeviceID]*event.Content)}
	for userID, sessions := range olmSessions {
		if len(sessions) == 0 {
			continue
		}
		output := make(map[id.DeviceID]*event.Content)
		toDevice.Messages[userID] = output
		for deviceID, device := range sessions {
			log.Trace().
				Stringer("target_user_id", userID).
				Stringer("target_device_id", deviceID).
				Stringer("target_identity_key", device.identity.IdentityKey).
				Msg("Encrypting group session for device")
			content := mach.encryptOlmEvent(ctx, device.session, device.identity, event.ToDeviceRoomKey, session.ShareContent())
			output[deviceID] = &event.Content{Parsed: content}
			deviceCount++
			log.Debug().
				Stringer("target_user_id", userID).
				Stringer("target_device_id", deviceID).
				Stringer("target_identity_key", device.identity.IdentityKey).
				Msg("Encrypted group session for device")
			if !mach.DisableSharedGroupSessionTracking {
				err := mach.CryptoStore.MarkOutboundGroupSessionShared(ctx, userID, device.identity.IdentityKey, session.id)
				if err != nil {
					log.Warn().
						Err(err).
						Stringer("target_user_id", userID).
						Stringer("target_device_id", deviceID).
						Stringer("target_identity_key", device.identity.IdentityKey).
						Stringer("target_session_id", session.id).
						Msg("Failed to mark outbound group session shared")
				}
			}
		}
	}

	log.Debug().
		Int("device_count", deviceCount).
		Int("user_count", len(toDevice.Messages)).
		Msg("Sending to-device messages to share group session")
	_, err := mach.Client.SendToDevice(ctx, event.ToDeviceEncrypted, toDevice)
	return err
}

func (mach *OlmMachine) findOlmSessionsForUser(ctx context.Context, session *OutboundGroupSession, userID id.UserID, devices map[id.DeviceID]*id.Device, output map[id.DeviceID]deviceSessionWrapper, withheld map[id.DeviceID]*event.Content, missingOutput map[id.DeviceID]*id.Device) {
	for deviceID, device := range devices {
		log := zerolog.Ctx(ctx).With().
			Stringer("target_user_id", userID).
			Stringer("target_device_id", deviceID).
			Stringer("target_identity_key", device.IdentityKey).
			Logger()
		userKey := UserDevice{UserID: userID, DeviceID: deviceID}
		if state := session.Users[userKey]; state != OGSNotShared {
			continue
		} else if userID == mach.Client.UserID && deviceID == mach.Client.DeviceID {
			session.Users[userKey] = OGSIgnored
		} else if device.Trust == id.TrustStateBlacklisted {
			log.Debug().Msg("Not encrypting group session for device: device is blacklisted")
			withheld[deviceID] = &event.Content{Parsed: &event.RoomKeyWithheldEventContent{
				RoomID:    session.RoomID,
				Algorithm: id.AlgorithmMegolmV1,
				SessionID: session.ID(),
				SenderKey: mach.account.IdentityKey(),
				Code:      event.RoomKeyWithheldBlacklisted,
				Reason:    "Device is blacklisted",
			}}
			session.Users[userKey] = OGSIgnored
		} else if trustState, _ := mach.ResolveTrustContext(ctx, device); trustState < mach.SendKeysMinTrust {
			log.Debug().
				Str("min_trust", mach.SendKeysMinTrust.String()).
				Str("device_trust", trustState.String()).
				Msg("Not encrypting group session for device: device is not trusted")
			withheld[deviceID] = &event.Content{Parsed: &event.RoomKeyWithheldEventContent{
				RoomID:    session.RoomID,
				Algorithm: id.AlgorithmMegolmV1,
				SessionID: session.ID(),
				SenderKey: mach.account.IdentityKey(),
				Code:      event.RoomKeyWithheldUnverified,
				Reason:    "This device does not encrypt messages for unverified devices",
			}}
			session.Users[userKey] = OGSIgnored
		} else if deviceSession, err := mach.CryptoStore.GetLatestSession(ctx, device.IdentityKey); err != nil {
			log.Error().Err(err).Msg("Failed to get olm session to encrypt group session")
		} else if deviceSession == nil {
			log.Warn().Err(err).Msg("Didn't find olm session to encrypt group session")
			if missingOutput != nil {
				missingOutput[deviceID] = device
			}
		} else {
			output[deviceID] = deviceSessionWrapper{
				session:  deviceSession,
				identity: device,
			}
			session.Users[userKey] = OGSAlreadyShared
		}
	}
}
