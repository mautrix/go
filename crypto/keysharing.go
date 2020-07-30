// Copyright (c) 2020 Nikos Filippakis
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

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
	mach.Log.Trace("Created inbound group session %s/%s/%s", content.RoomID, content.SenderKey, content.SessionID)
	return true
}

func (mach *OlmMachine) handleRoomKeyRequest(sender id.UserID, content *event.RoomKeyRequestEventContent, allowUnverified bool) {
	// Only forward keys to the same user ID
	if content.Action == event.KeyRequestActionRequest && mach.Client.UserID == sender {
		if content.RequestingDeviceID == mach.Client.DeviceID {
			mach.Log.Debug("Ignoring key request from the same device (%v)", content.RequestingDeviceID)
			return
		}
		mach.Log.Debug("Received key request from %v for session %v", content.RequestingDeviceID, content.Body.SessionID)

		// fetch requesting device identity
		device, err := mach.GetOrFetchDevice(sender, content.RequestingDeviceID)
		if err != nil {
			mach.Log.Error("Error getting key requesting device: %v", err)
			return
		}
		// ignore if not verified and we do not allow unverified
		if device.Trust != TrustStateVerified && !allowUnverified {
			mach.Log.Warn("Device %v requesting room keys is not verified, ignoring", device.DeviceID)
			return
		}

		igs, err := mach.CryptoStore.GetGroupSession(content.Body.RoomID, content.Body.SenderKey, content.Body.SessionID)
		if err != nil {
			mach.Log.Error("Error retrieving IGS to forward key: %v", err)
			return
		}
		if igs == nil {
			mach.Log.Warn("Can't find the requested session to forward: %v", content.Body.SessionID)
			return
		}

		// export session key at earliest index
		exportedKey, err := igs.Internal.Export(igs.Internal.FirstKnownIndex())
		if err != nil {
			mach.Log.Error("Error exporting key for session %v: %v", igs.ID(), err)
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

		if err := mach.SendEncryptedToDevice(device, forwardedRoomKey); err != nil {
			mach.Log.Error("Failed to send encrypted forwarded key: %v", err)
		}

		mach.Log.Debug("Sent encrypted forwarded key to device %v for session %v", content.RequestingDeviceID, igs.ID())
	}
}
