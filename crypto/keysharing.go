// Copyright (c) 2020 Nikos Filippakis
// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"
	"errors"
	"time"

	"github.com/rs/zerolog"

	"github.com/element-hq/mautrix-go/crypto/olm"
	"github.com/element-hq/mautrix-go/id"

	"github.com/element-hq/mautrix-go"
	"github.com/element-hq/mautrix-go/event"
)

type KeyShareRejection struct {
	Code   event.RoomKeyWithheldCode
	Reason string
}

var (
	// Reject a key request without responding
	KeyShareRejectNoResponse = KeyShareRejection{}

	KeyShareRejectBlacklisted   = KeyShareRejection{event.RoomKeyWithheldBlacklisted, "You have been blacklisted by this device"}
	KeyShareRejectUnverified    = KeyShareRejection{event.RoomKeyWithheldUnverified, "This device does not share keys to unverified devices"}
	KeyShareRejectOtherUser     = KeyShareRejection{event.RoomKeyWithheldUnauthorized, "This device does not share keys to other users"}
	KeyShareRejectUnavailable   = KeyShareRejection{event.RoomKeyWithheldUnavailable, "Requested session ID not found on this device"}
	KeyShareRejectInternalError = KeyShareRejection{event.RoomKeyWithheldUnavailable, "An internal error occurred while trying to share the requested session"}
)

// RequestRoomKey sends a key request for a room to the current user's devices. If the context is cancelled, then so is the key request.
// Returns a bool channel that will get notified either when the key is received or the request is cancelled.
//
// Deprecated: this only supports a single key request target, so the whole automatic cancelling feature isn't very useful.
func (mach *OlmMachine) RequestRoomKey(ctx context.Context, toUser id.UserID, toDevice id.DeviceID,
	roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID) (chan bool, error) {

	requestID := mach.Client.TxnID()
	keyResponseReceived := make(chan struct{})
	mach.roomKeyRequestFilled.Store(sessionID, keyResponseReceived)

	err := mach.SendRoomKeyRequest(ctx, roomID, senderKey, sessionID, requestID, map[id.UserID][]id.DeviceID{toUser: {toDevice}})
	if err != nil {
		return nil, err
	}

	resChan := make(chan bool, 1)
	go func() {
		select {
		case <-keyResponseReceived:
			// key request successful
			mach.Log.Debug().Msgf("Key for session %v was received, cancelling other key requests", sessionID)
			resChan <- true
		case <-ctx.Done():
			// if the context is done, key request was unsuccessful
			mach.Log.Debug().Msgf("Context closed (%v) before forwared key for session %v received, sending key request cancellation", ctx.Err(), sessionID)
			resChan <- false
		}

		// send a message to all devices cancelling this key request
		mach.roomKeyRequestFilled.Delete(sessionID)

		cancelEvtContent := &event.Content{
			Parsed: event.RoomKeyRequestEventContent{
				Action:             event.KeyRequestActionCancel,
				RequestID:          requestID,
				RequestingDeviceID: mach.Client.DeviceID,
			},
		}

		toDeviceCancel := &mautrix.ReqSendToDevice{
			Messages: map[id.UserID]map[id.DeviceID]*event.Content{
				toUser: {
					toDevice: cancelEvtContent,
				},
			},
		}

		mach.Client.SendToDevice(ctx, event.ToDeviceRoomKeyRequest, toDeviceCancel)
	}()
	return resChan, nil
}

// SendRoomKeyRequest sends a key request for the given key (identified by the room ID, sender key and session ID) to the given users.
//
// The request ID parameter is optional. If it's empty, a random ID will be generated.
//
// This function does not wait for the keys to arrive. You can use WaitForSession to wait for the session to
// arrive (in any way, not just as a reply to this request). There's also RequestRoomKey which waits for a response
// to the specific key request, but currently it only supports a single target device and is therefore deprecated.
// A future function may properly support multiple targets and automatically canceling the other requests when receiving
// the first response.
func (mach *OlmMachine) SendRoomKeyRequest(ctx context.Context, roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID, requestID string, users map[id.UserID][]id.DeviceID) error {
	if len(requestID) == 0 {
		requestID = mach.Client.TxnID()
	}
	requestEvent := &event.Content{
		Parsed: &event.RoomKeyRequestEventContent{
			Action: event.KeyRequestActionRequest,
			Body: event.RequestedKeyInfo{
				Algorithm: id.AlgorithmMegolmV1,
				RoomID:    roomID,
				SenderKey: senderKey,
				SessionID: sessionID,
			},
			RequestID:          requestID,
			RequestingDeviceID: mach.Client.DeviceID,
		},
	}

	toDeviceReq := &mautrix.ReqSendToDevice{
		Messages: make(map[id.UserID]map[id.DeviceID]*event.Content, len(users)),
	}
	for user, devices := range users {
		toDeviceReq.Messages[user] = make(map[id.DeviceID]*event.Content, len(devices))
		for _, device := range devices {
			toDeviceReq.Messages[user][device] = requestEvent
		}
	}
	_, err := mach.Client.SendToDevice(ctx, event.ToDeviceRoomKeyRequest, toDeviceReq)
	return err
}

func (mach *OlmMachine) importForwardedRoomKey(ctx context.Context, evt *DecryptedOlmEvent, content *event.ForwardedRoomKeyEventContent) bool {
	log := zerolog.Ctx(ctx).With().
		Str("session_id", content.SessionID.String()).
		Str("room_id", content.RoomID.String()).
		Logger()
	if content.Algorithm != id.AlgorithmMegolmV1 || evt.Keys.Ed25519 == "" {
		log.Debug().
			Str("algorithm", string(content.Algorithm)).
			Msg("Ignoring weird forwarded room key")
		return false
	}

	igsInternal, err := olm.InboundGroupSessionImport([]byte(content.SessionKey))
	if err != nil {
		log.Error().Err(err).Msg("Failed to import inbound group session")
		return false
	} else if igsInternal.ID() != content.SessionID {
		log.Warn().
			Str("actual_session_id", igsInternal.ID().String()).
			Msg("Mismatched session ID while creating inbound group session from forward")
		return false
	}
	config, err := mach.StateStore.GetEncryptionEvent(ctx, content.RoomID)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get encryption event for room")
	}
	var maxAge time.Duration
	var maxMessages int
	if config != nil {
		maxAge = time.Duration(config.RotationPeriodMillis) * time.Millisecond
		maxMessages = config.RotationPeriodMessages
	}
	if content.MaxAge != 0 {
		maxAge = time.Duration(content.MaxAge) * time.Millisecond
	}
	if content.MaxMessages != 0 {
		maxMessages = content.MaxMessages
	}
	igs := &InboundGroupSession{
		Internal:         *igsInternal,
		SigningKey:       evt.Keys.Ed25519,
		SenderKey:        content.SenderKey,
		RoomID:           content.RoomID,
		ForwardingChains: append(content.ForwardingKeyChain, evt.SenderKey.String()),
		id:               content.SessionID,

		ReceivedAt:  time.Now().UTC(),
		MaxAge:      maxAge.Milliseconds(),
		MaxMessages: maxMessages,
		IsScheduled: content.IsScheduled,
	}
	err = mach.CryptoStore.PutGroupSession(ctx, content.RoomID, content.SenderKey, content.SessionID, igs)
	if err != nil {
		log.Error().Err(err).Msg("Failed to store new inbound group session")
		return false
	}
	mach.markSessionReceived(content.SessionID)
	log.Debug().Msg("Received forwarded inbound group session")
	return true
}

func (mach *OlmMachine) rejectKeyRequest(ctx context.Context, rejection KeyShareRejection, device *id.Device, request event.RequestedKeyInfo) {
	if rejection.Code == "" {
		// If the rejection code is empty, it means don't share keys, but also don't tell the requester.
		return
	}
	content := event.RoomKeyWithheldEventContent{
		RoomID:    request.RoomID,
		Algorithm: request.Algorithm,
		SessionID: request.SessionID,
		SenderKey: request.SenderKey,
		Code:      rejection.Code,
		Reason:    rejection.Reason,
	}
	err := mach.sendToOneDevice(ctx, device.UserID, device.DeviceID, event.ToDeviceRoomKeyWithheld, &content)
	if err != nil {
		mach.Log.Warn().Err(err).
			Str("code", string(rejection.Code)).
			Str("user_id", device.UserID.String()).
			Str("device_id", device.DeviceID.String()).
			Msg("Failed to send key share rejection")
	}
	err = mach.sendToOneDevice(ctx, device.UserID, device.DeviceID, event.ToDeviceOrgMatrixRoomKeyWithheld, &content)
	if err != nil {
		mach.Log.Warn().Err(err).
			Str("code", string(rejection.Code)).
			Str("user_id", device.UserID.String()).
			Str("device_id", device.DeviceID.String()).
			Msg("Failed to send key share rejection (legacy event type)")
	}
}

func (mach *OlmMachine) defaultAllowKeyShare(ctx context.Context, device *id.Device, _ event.RequestedKeyInfo) *KeyShareRejection {
	log := mach.machOrContextLog(ctx)
	if mach.Client.UserID != device.UserID {
		log.Debug().Msg("Rejecting key request from a different user")
		return &KeyShareRejectOtherUser
	} else if mach.Client.DeviceID == device.DeviceID {
		log.Debug().Msg("Ignoring key request from ourselves")
		return &KeyShareRejectNoResponse
	} else if device.Trust == id.TrustStateBlacklisted {
		log.Debug().Msg("Rejecting key request from blacklisted device")
		return &KeyShareRejectBlacklisted
	} else if trustState := mach.ResolveTrust(device); trustState >= mach.ShareKeysMinTrust {
		log.Debug().
			Str("min_trust", mach.SendKeysMinTrust.String()).
			Str("device_trust", trustState.String()).
			Msg("Accepting key request from trusted device")
		return nil
	} else {
		log.Debug().
			Str("min_trust", mach.SendKeysMinTrust.String()).
			Str("device_trust", trustState.String()).
			Msg("Rejecting key request from untrusted device")
		return &KeyShareRejectUnverified
	}
}

func (mach *OlmMachine) handleRoomKeyRequest(ctx context.Context, sender id.UserID, content *event.RoomKeyRequestEventContent) {
	log := zerolog.Ctx(ctx).With().
		Str("request_id", content.RequestID).
		Str("device_id", content.RequestingDeviceID.String()).
		Str("room_id", content.Body.RoomID.String()).
		Str("session_id", content.Body.SessionID.String()).
		Logger()
	ctx = log.WithContext(ctx)
	if content.Action != event.KeyRequestActionRequest {
		return
	} else if content.RequestingDeviceID == mach.Client.DeviceID && sender == mach.Client.UserID {
		log.Debug().Msg("Ignoring key request from ourselves")
		return
	}

	log.Debug().Msg("Received key request")

	device, err := mach.GetOrFetchDevice(ctx, sender, content.RequestingDeviceID)
	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch device that requested keys")
		return
	}

	rejection := mach.AllowKeyShare(ctx, device, content.Body)
	if rejection != nil {
		mach.rejectKeyRequest(ctx, *rejection, device, content.Body)
		return
	}

	igs, err := mach.CryptoStore.GetGroupSession(ctx, content.Body.RoomID, content.Body.SenderKey, content.Body.SessionID)
	if err != nil {
		if errors.Is(err, ErrGroupSessionWithheld) {
			log.Debug().Err(err).Msg("Requested group session not available")
			mach.rejectKeyRequest(ctx, KeyShareRejectUnavailable, device, content.Body)
		} else {
			log.Error().Err(err).Msg("Failed to get group session to forward")
			mach.rejectKeyRequest(ctx, KeyShareRejectInternalError, device, content.Body)
		}
		return
	} else if igs == nil {
		log.Error().Msg("Didn't find group session to forward")
		mach.rejectKeyRequest(ctx, KeyShareRejectUnavailable, device, content.Body)
		return
	}
	if internalID := igs.ID(); internalID != content.Body.SessionID {
		// Should this be an error?
		log = log.With().Str("unexpected_session_id", internalID.String()).Logger()
	}

	firstKnownIndex := igs.Internal.FirstKnownIndex()
	log = log.With().Uint32("first_known_index", firstKnownIndex).Logger()
	exportedKey, err := igs.Internal.Export(firstKnownIndex)
	if err != nil {
		log.Error().Err(err).Msg("Failed to export group session to forward")
		mach.rejectKeyRequest(ctx, KeyShareRejectInternalError, device, content.Body)
		return
	}

	forwardedRoomKey := event.Content{
		Parsed: &event.ForwardedRoomKeyEventContent{
			RoomKeyEventContent: event.RoomKeyEventContent{
				Algorithm:  id.AlgorithmMegolmV1,
				RoomID:     igs.RoomID,
				SessionID:  igs.ID(),
				SessionKey: string(exportedKey),
			},
			SenderKey:          content.Body.SenderKey,
			ForwardingKeyChain: igs.ForwardingChains,
			SenderClaimedKey:   igs.SigningKey,
		},
	}

	if err = mach.SendEncryptedToDevice(ctx, device, event.ToDeviceForwardedRoomKey, forwardedRoomKey); err != nil {
		log.Error().Err(err).Msg("Failed to encrypt and send group session")
	} else {
		log.Debug().Msg("Successfully sent forwarded group session")
	}
}

func (mach *OlmMachine) handleBeeperRoomKeyAck(ctx context.Context, sender id.UserID, content *event.BeeperRoomKeyAckEventContent) {
	log := mach.machOrContextLog(ctx).With().
		Str("room_id", content.RoomID.String()).
		Str("session_id", content.SessionID.String()).
		Int("first_message_index", content.FirstMessageIndex).
		Logger()

	sess, err := mach.CryptoStore.GetGroupSession(ctx, content.RoomID, "", content.SessionID)
	if err != nil {
		if errors.Is(err, ErrGroupSessionWithheld) {
			log.Debug().Err(err).Msg("Acked group session was already redacted")
		} else {
			log.Err(err).Msg("Failed to get group session to check if it should be redacted")
		}
		return
	} else if sess == nil {
		log.Warn().Msg("Got key backup ack for unknown session")
		return
	}
	log = log.With().
		Str("sender_key", sess.SenderKey.String()).
		Str("own_identity", mach.OwnIdentity().IdentityKey.String()).
		Logger()

	isInbound := sess.SenderKey == mach.OwnIdentity().IdentityKey
	if isInbound && mach.DeleteOutboundKeysOnAck && content.FirstMessageIndex == 0 {
		log.Debug().Msg("Redacting inbound copy of outbound group session after ack")
		err = mach.CryptoStore.RedactGroupSession(ctx, content.RoomID, sess.SenderKey, content.SessionID, "outbound session acked")
		if err != nil {
			log.Err(err).Msg("Failed to redact group session")
		}
	} else {
		log.Debug().Bool("inbound", isInbound).Msg("Received room key ack")
	}
}
