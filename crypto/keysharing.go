// Copyright (c) 2020 Nikos Filippakis
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build !nosas
// +build !nosas

package crypto

import (
	"context"
	"math/rand"
	"strconv"

	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/id"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
)

type KeyShareRejection struct {
	Code   event.RoomKeyWithheldCode
	Reason string
}

var (
	// Reject a key request without responding
	KeyShareRejectNoResponse = KeyShareRejection{}

	KeyShareRejectBlacklisted   = KeyShareRejection{event.RoomKeyWithheldBlacklisted, "You have been blacklisted by this device"}
	KeyShareRejectUnverified    = KeyShareRejection{event.RoomKeyWithheldUnverified, "You have not been verified by this device"}
	KeyShareRejectOtherUser     = KeyShareRejection{event.RoomKeyWithheldUnauthorized, "This device does not share keys to other users"}
	KeyShareRejectUnavailable   = KeyShareRejection{event.RoomKeyWithheldUnavailable, "Requested session ID not found on this device"}
	KeyShareRejectInternalError = KeyShareRejection{event.RoomKeyWithheldUnavailable, "An internal error occurred while trying to share the requested session"}
)

// RequestRoomKey sends a key request for a room to the current user's devices. If the context is cancelled, then so is the key request.
// Returns a bool channel that will get notified either when the key is received or the request is cancelled.
func (mach *OlmMachine) RequestRoomKey(ctx context.Context, toUser id.UserID, toDevice id.DeviceID,
	roomID id.RoomID, senderKey id.SenderKey, sessionID id.SessionID) (chan bool, error) {

	requestID := strconv.Itoa(rand.Int())
	keyResponseReceived := make(chan struct{})
	// store the channel where we will be notified about responses for this session ID
	mach.roomKeyRequestFilled.Store(sessionID, keyResponseReceived)
	// request the keys for this session
	reqEvtContent := &event.Content{
		Parsed: event.RoomKeyRequestEventContent{
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
		Messages: map[id.UserID]map[id.DeviceID]*event.Content{
			toUser: {
				toDevice: reqEvtContent,
			},
		},
	}
	// send messages to the devices
	if _, err := mach.Client.SendToDevice(event.ToDeviceRoomKeyRequest, toDeviceReq); err != nil {
		return nil, err
	}
	resChan := make(chan bool, 1)
	go func() {
		select {
		case <-keyResponseReceived:
			// key request successful
			mach.Log.Debug("Key for session %v was received, cancelling other key requests", sessionID)
			resChan <- true
		case <-ctx.Done():
			// if the context is done, key request was unsuccessful
			mach.Log.Debug("Context closed (%v) before forwared key for session %v received, sending key request cancellation", ctx.Err(), sessionID)
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

		mach.Client.SendToDevice(event.ToDeviceRoomKeyRequest, toDeviceCancel)
	}()
	return resChan, nil
}

func (mach *OlmMachine) importForwardedRoomKey(evt *DecryptedOlmEvent, content *event.ForwardedRoomKeyEventContent) bool {
	if content.Algorithm != id.AlgorithmMegolmV1 || evt.Keys.Ed25519 == "" {
		mach.Log.Debug("Ignoring weird forwarded room key from %s/%s: alg=%s, ed25519=%s, sessionid=%s, roomid=%s", evt.Sender, evt.SenderDevice, content.Algorithm, evt.Keys.Ed25519, content.SessionID, content.RoomID)
		return false
	}

	igsInternal, err := olm.InboundGroupSessionImport([]byte(content.SessionKey))
	if err != nil {
		mach.Log.Error("Failed to import inbound group session: %v", err)
		return false
	} else if igsInternal.ID() != content.SessionID {
		mach.Log.Warn("Mismatched session ID while creating inbound group session")
		return false
	}
	igs := &InboundGroupSession{
		Internal:         *igsInternal,
		SigningKey:       evt.Keys.Ed25519,
		SenderKey:        content.SenderKey,
		RoomID:           content.RoomID,
		ForwardingChains: append(content.ForwardingKeyChain, evt.SenderKey.String()),
		id:               content.SessionID,
	}
	err = mach.CryptoStore.PutGroupSession(content.RoomID, content.SenderKey, content.SessionID, igs)
	if err != nil {
		mach.Log.Error("Failed to store new inbound group session: %v", err)
		return false
	}
	mach.markSessionReceived(content.SessionID)
	mach.Log.Trace("Received forwarded inbound group session %s/%s/%s", content.RoomID, content.SenderKey, content.SessionID)
	return true
}

func (mach *OlmMachine) rejectKeyRequest(rejection KeyShareRejection, device *DeviceIdentity, request event.RequestedKeyInfo) {
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
	err := mach.sendToOneDevice(device.UserID, device.DeviceID, event.ToDeviceRoomKeyWithheld, &content)
	if err != nil {
		mach.Log.Warn("Failed to send key share rejection %s to %s/%s: %v", rejection.Code, device.UserID, device.DeviceID, err)
	}
	err = mach.sendToOneDevice(device.UserID, device.DeviceID, event.ToDeviceOrgMatrixRoomKeyWithheld, &content)
	if err != nil {
		mach.Log.Warn("Failed to send key share rejection %s (org.matrix.) to %s/%s: %v", rejection.Code, device.UserID, device.DeviceID, err)
	}
}

func (mach *OlmMachine) defaultAllowKeyShare(device *DeviceIdentity, _ event.RequestedKeyInfo) *KeyShareRejection {
	if mach.Client.UserID != device.UserID {
		mach.Log.Debug("Ignoring key request from a different user (%s)", device.UserID)
		return &KeyShareRejectOtherUser
	} else if mach.Client.DeviceID == device.DeviceID {
		mach.Log.Debug("Ignoring key request from ourselves")
		return &KeyShareRejectNoResponse
	} else if device.Trust == TrustStateBlacklisted {
		mach.Log.Debug("Ignoring key request from blacklisted device %s", device.DeviceID)
		return &KeyShareRejectBlacklisted
	} else if mach.IsDeviceTrusted(device) {
		mach.Log.Debug("Accepting key request from verified device %s", device.DeviceID)
		return nil
	} else if mach.ShareKeysToUnverifiedDevices {
		mach.Log.Debug("Accepting key request from unverified device %s (ShareKeysToUnverifiedDevices is true)", device.DeviceID)
		return nil
	} else {
		mach.Log.Debug("Ignoring key request from unverified device %s", device.DeviceID)
		return &KeyShareRejectUnverified
	}
}

func (mach *OlmMachine) handleRoomKeyRequest(sender id.UserID, content *event.RoomKeyRequestEventContent) {
	if content.Action != event.KeyRequestActionRequest {
		return
	} else if content.RequestingDeviceID == mach.Client.DeviceID && sender == mach.Client.UserID {
		mach.Log.Debug("Ignoring key request %s from ourselves", content.RequestID)
		return
	}

	mach.Log.Debug("Received key request %s for %s from %s/%s", content.RequestID, content.Body.SessionID, sender, content.RequestingDeviceID)

	device, err := mach.GetOrFetchDevice(sender, content.RequestingDeviceID)
	if err != nil {
		mach.Log.Error("Failed to fetch device %s/%s that requested keys: %v", sender, content.RequestingDeviceID, err)
		return
	}

	rejection := mach.AllowKeyShare(device, content.Body)
	if rejection != nil {
		mach.rejectKeyRequest(*rejection, device, content.Body)
		return
	}

	igs, err := mach.CryptoStore.GetGroupSession(content.Body.RoomID, content.Body.SenderKey, content.Body.SessionID)
	if err != nil {
		mach.Log.Error("Failed to fetch group session to forward to %s/%s: %v", device.UserID, device.DeviceID, err)
		mach.rejectKeyRequest(KeyShareRejectInternalError, device, content.Body)
		return
	} else if igs == nil {
		mach.Log.Warn("Didn't find group session %s to forward to %s/%s", content.Body.SessionID, device.UserID, device.DeviceID)
		mach.rejectKeyRequest(KeyShareRejectUnavailable, device, content.Body)
		return
	}

	exportedKey, err := igs.Internal.Export(igs.Internal.FirstKnownIndex())
	if err != nil {
		mach.Log.Error("Failed to export session %s to forward to %s/%s: %v", igs.ID(), device.UserID, device.DeviceID, err)
		mach.rejectKeyRequest(KeyShareRejectInternalError, device, content.Body)
		return
	}

	forwardedRoomKey := event.Content{
		Parsed: &event.ForwardedRoomKeyEventContent{
			RoomKeyEventContent: event.RoomKeyEventContent{
				Algorithm:  id.AlgorithmMegolmV1,
				RoomID:     igs.RoomID,
				SessionID:  igs.ID(),
				SessionKey: exportedKey,
			},
			SenderKey:          content.Body.SenderKey,
			ForwardingKeyChain: igs.ForwardingChains,
			SenderClaimedKey:   igs.SigningKey,
		},
	}

	if err := mach.SendEncryptedToDevice(device, event.ToDeviceForwardedRoomKey, forwardedRoomKey); err != nil {
		mach.Log.Error("Failed to send encrypted forwarded key %s to %s/%s: %v", igs.ID(), device.UserID, device.DeviceID, err)
	}

	mach.Log.Debug("Sent encrypted forwarded key to device %s/%s for session %s", device.UserID, device.DeviceID, igs.ID())
}
