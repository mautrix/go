// Copyright (c) 2020 Nikos Filippakis
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/element-hq/mautrix-go/crypto/canonicaljson"
	"github.com/element-hq/mautrix-go/crypto/olm"
	"github.com/element-hq/mautrix-go/event"
	"github.com/element-hq/mautrix-go/id"
)

var (
	ErrNoVerificationFromDevice = errors.New("from_device field is empty")
	ErrNoVerificationMethods    = errors.New("verification method list is empty")
	ErrNoRelatesTo              = errors.New("missing m.relates_to info")
)

// ProcessInRoomVerification is a callback that is to be called when a client receives a message
// related to in-room verification.
//
// Currently this is not automatically called, so you must add the listener yourself.
// Note that in-room verification events are wrapped in m.room.encrypted, but this expects the decrypted events.
func (mach *OlmMachine) ProcessInRoomVerification(evt *event.Event) error {
	if evt.Sender == mach.Client.UserID {
		// nothing to do if the message is our own
		return nil
	}
	if relatable, ok := evt.Content.Parsed.(event.Relatable); !ok || relatable.OptionalGetRelatesTo() == nil {
		return ErrNoRelatesTo
	}

	ctx := context.TODO()
	switch content := evt.Content.Parsed.(type) {
	case *event.MessageEventContent:
		if content.MsgType == event.MsgVerificationRequest {
			if content.FromDevice == "" {
				return ErrNoVerificationFromDevice
			}
			if content.Methods == nil {
				return ErrNoVerificationMethods
			}

			newContent := &event.VerificationRequestEventContent{
				FromDevice:    content.FromDevice,
				Methods:       content.Methods,
				Timestamp:     evt.Timestamp,
				TransactionID: evt.ID.String(),
			}
			mach.handleVerificationRequest(ctx, evt.Sender, newContent, evt.ID.String(), evt.RoomID)
		}
	case *event.VerificationStartEventContent:
		mach.handleVerificationStart(ctx, evt.Sender, content, content.RelatesTo.EventID.String(), 10*time.Minute, evt.RoomID)
	case *event.VerificationReadyEventContent:
		mach.handleInRoomVerificationReady(ctx, evt.Sender, evt.RoomID, content, content.RelatesTo.EventID.String())
	case *event.VerificationAcceptEventContent:
		mach.handleVerificationAccept(ctx, evt.Sender, content, content.RelatesTo.EventID.String())
	case *event.VerificationKeyEventContent:
		mach.handleVerificationKey(ctx, evt.Sender, content, content.RelatesTo.EventID.String())
	case *event.VerificationMacEventContent:
		mach.handleVerificationMAC(ctx, evt.Sender, content, content.RelatesTo.EventID.String())
	case *event.VerificationCancelEventContent:
		mach.handleVerificationCancel(evt.Sender, content, content.RelatesTo.EventID.String())
	}
	return nil
}

// SendInRoomSASVerificationCancel is used to manually send an in-room SAS cancel message process with the given reason and cancellation code.
func (mach *OlmMachine) SendInRoomSASVerificationCancel(ctx context.Context, roomID id.RoomID, userID id.UserID, transactionID string, reason string, code event.VerificationCancelCode) error {
	content := &event.VerificationCancelEventContent{
		RelatesTo: &event.RelatesTo{Type: event.RelReference, EventID: id.EventID(transactionID)},
		Reason:    reason,
		Code:      code,
		To:        userID,
	}

	encrypted, err := mach.EncryptMegolmEvent(ctx, roomID, event.InRoomVerificationCancel, content)
	if err != nil {
		return err
	}
	_, err = mach.Client.SendMessageEvent(ctx, roomID, event.EventEncrypted, encrypted)
	return err
}

// SendInRoomSASVerificationRequest is used to manually send an in-room SAS verification request message to another user.
func (mach *OlmMachine) SendInRoomSASVerificationRequest(ctx context.Context, roomID id.RoomID, toUserID id.UserID, methods []VerificationMethod) (string, error) {
	content := &event.MessageEventContent{
		MsgType:    event.MsgVerificationRequest,
		FromDevice: mach.Client.DeviceID,
		Methods:    []event.VerificationMethod{event.VerificationMethodSAS},
		To:         toUserID,
	}

	encrypted, err := mach.EncryptMegolmEvent(ctx, roomID, event.EventMessage, content)
	if err != nil {
		return "", err
	}
	resp, err := mach.Client.SendMessageEvent(ctx, roomID, event.EventEncrypted, encrypted)
	if err != nil {
		return "", err
	}
	return resp.EventID.String(), nil
}

// SendInRoomSASVerificationReady is used to manually send an in-room SAS verification ready message to another user.
func (mach *OlmMachine) SendInRoomSASVerificationReady(ctx context.Context, roomID id.RoomID, transactionID string) error {
	content := &event.VerificationReadyEventContent{
		FromDevice: mach.Client.DeviceID,
		Methods:    []event.VerificationMethod{event.VerificationMethodSAS},
		RelatesTo:  &event.RelatesTo{Type: event.RelReference, EventID: id.EventID(transactionID)},
	}

	encrypted, err := mach.EncryptMegolmEvent(ctx, roomID, event.InRoomVerificationReady, content)
	if err != nil {
		return err
	}
	_, err = mach.Client.SendMessageEvent(ctx, roomID, event.EventEncrypted, encrypted)
	return err
}

// SendInRoomSASVerificationStart is used to manually send the in-room SAS verification start message to another user.
func (mach *OlmMachine) SendInRoomSASVerificationStart(ctx context.Context, roomID id.RoomID, toUserID id.UserID, transactionID string, methods []VerificationMethod) (*event.VerificationStartEventContent, error) {
	sasMethods := make([]event.SASMethod, len(methods))
	for i, method := range methods {
		sasMethods[i] = method.Type()
	}
	content := &event.VerificationStartEventContent{
		FromDevice:                 mach.Client.DeviceID,
		RelatesTo:                  &event.RelatesTo{Type: event.RelReference, EventID: id.EventID(transactionID)},
		Method:                     event.VerificationMethodSAS,
		KeyAgreementProtocols:      []event.KeyAgreementProtocol{event.KeyAgreementCurve25519HKDFSHA256},
		Hashes:                     []event.VerificationHashMethod{event.VerificationHashSHA256},
		MessageAuthenticationCodes: []event.MACMethod{event.HKDFHMACSHA256},
		ShortAuthenticationString:  sasMethods,
		To:                         toUserID,
	}

	encrypted, err := mach.EncryptMegolmEvent(ctx, roomID, event.InRoomVerificationStart, content)
	if err != nil {
		return nil, err
	}
	_, err = mach.Client.SendMessageEvent(ctx, roomID, event.EventEncrypted, encrypted)
	return content, err
}

// SendInRoomSASVerificationAccept is used to manually send an accept for an in-room SAS verification process from a received m.key.verification.start event.
func (mach *OlmMachine) SendInRoomSASVerificationAccept(ctx context.Context, roomID id.RoomID, fromUser id.UserID, startEvent *event.VerificationStartEventContent, transactionID string, publicKey []byte, methods []VerificationMethod) error {
	if startEvent.Method != event.VerificationMethodSAS {
		reason := "Unknown verification method: " + string(startEvent.Method)
		if err := mach.SendInRoomSASVerificationCancel(ctx, roomID, fromUser, transactionID, reason, event.VerificationCancelUnknownMethod); err != nil {
			return err
		}
		return ErrUnknownVerificationMethod
	}
	payload, err := json.Marshal(startEvent)
	if err != nil {
		return err
	}
	canonical, err := canonicaljson.CanonicalJSON(payload)
	if err != nil {
		return err
	}
	hash := olm.NewUtility().Sha256(string(publicKey) + string(canonical))
	sasMethods := make([]event.SASMethod, len(methods))
	for i, method := range methods {
		sasMethods[i] = method.Type()
	}
	content := &event.VerificationAcceptEventContent{
		RelatesTo:                 &event.RelatesTo{Type: event.RelReference, EventID: id.EventID(transactionID)},
		Method:                    event.VerificationMethodSAS,
		KeyAgreementProtocol:      event.KeyAgreementCurve25519HKDFSHA256,
		Hash:                      event.VerificationHashSHA256,
		MessageAuthenticationCode: event.HKDFHMACSHA256,
		ShortAuthenticationString: sasMethods,
		Commitment:                hash,
		To:                        fromUser,
	}

	encrypted, err := mach.EncryptMegolmEvent(ctx, roomID, event.InRoomVerificationAccept, content)
	if err != nil {
		return err
	}
	_, err = mach.Client.SendMessageEvent(ctx, roomID, event.EventEncrypted, encrypted)
	return err
}

// SendInRoomSASVerificationKey sends the ephemeral public key for a device to the partner device for an in-room verification.
func (mach *OlmMachine) SendInRoomSASVerificationKey(ctx context.Context, roomID id.RoomID, userID id.UserID, transactionID string, key string) error {
	content := &event.VerificationKeyEventContent{
		RelatesTo: &event.RelatesTo{Type: event.RelReference, EventID: id.EventID(transactionID)},
		Key:       key,
		To:        userID,
	}

	encrypted, err := mach.EncryptMegolmEvent(ctx, roomID, event.InRoomVerificationKey, content)
	if err != nil {
		return err
	}
	_, err = mach.Client.SendMessageEvent(ctx, roomID, event.EventEncrypted, encrypted)
	return err
}

// SendInRoomSASVerificationMAC sends the MAC of a device's key to the partner device for an in-room verification.
func (mach *OlmMachine) SendInRoomSASVerificationMAC(ctx context.Context, roomID id.RoomID, userID id.UserID, deviceID id.DeviceID, transactionID string, sas *olm.SAS) error {
	keyID := id.NewKeyID(id.KeyAlgorithmEd25519, mach.Client.DeviceID.String())

	signingKey := mach.account.SigningKey()
	keyIDsMap := map[id.KeyID]string{keyID: ""}
	macMap := make(map[id.KeyID]string)

	if mach.CrossSigningKeys != nil {
		masterKey := mach.CrossSigningKeys.MasterKey.PublicKey
		masterKeyID := id.NewKeyID(id.KeyAlgorithmEd25519, masterKey.String())
		// add master key ID to key map
		keyIDsMap[masterKeyID] = ""
		masterKeyMAC, _, err := mach.getPKAndKeysMAC(sas, mach.Client.UserID, mach.Client.DeviceID,
			userID, deviceID, transactionID, masterKey, masterKeyID, keyIDsMap)
		if err != nil {
			mach.Log.Error().Msgf("Error generating master key MAC: %v", err)
		} else {
			mach.Log.Debug().Msgf("Generated master key `%v` MAC: %v", masterKey, masterKeyMAC)
			macMap[masterKeyID] = masterKeyMAC
		}
	}

	pubKeyMac, keysMac, err := mach.getPKAndKeysMAC(sas, mach.Client.UserID, mach.Client.DeviceID, userID, deviceID, transactionID, signingKey, keyID, keyIDsMap)
	if err != nil {
		return err
	}
	mach.Log.Debug().Msgf("MAC of key %s is: %s", signingKey, pubKeyMac)
	mach.Log.Debug().Msgf("MAC of key ID(s) %s is: %s", keyID, keysMac)
	macMap[keyID] = pubKeyMac

	content := &event.VerificationMacEventContent{
		RelatesTo: &event.RelatesTo{Type: event.RelReference, EventID: id.EventID(transactionID)},
		Keys:      keysMac,
		Mac:       macMap,
		To:        userID,
	}

	encrypted, err := mach.EncryptMegolmEvent(ctx, roomID, event.InRoomVerificationMAC, content)
	if err != nil {
		return err
	}
	_, err = mach.Client.SendMessageEvent(ctx, roomID, event.EventEncrypted, encrypted)
	return err
}

// NewInRoomSASVerificationWith starts the in-room SAS verification process with another user in the given room.
// It returns the generated transaction ID.
func (mach *OlmMachine) NewInRoomSASVerificationWith(ctx context.Context, inRoomID id.RoomID, userID id.UserID, hooks VerificationHooks, timeout time.Duration) (string, error) {
	return mach.newInRoomSASVerificationWithInner(ctx, inRoomID, &id.Device{UserID: userID}, hooks, "", timeout)
}

func (mach *OlmMachine) newInRoomSASVerificationWithInner(ctx context.Context, inRoomID id.RoomID, device *id.Device, hooks VerificationHooks, transactionID string, timeout time.Duration) (string, error) {
	mach.Log.Debug().Msgf("Starting new in-room verification transaction user %v", device.UserID)

	request := transactionID == ""
	if request {
		var err error
		// get new transaction ID from the request message event ID
		transactionID, err = mach.SendInRoomSASVerificationRequest(ctx, inRoomID, device.UserID, hooks.VerificationMethods())
		if err != nil {
			return "", err
		}
	}
	verState := &verificationState{
		sas:                 olm.NewSAS(),
		otherDevice:         device,
		initiatedByUs:       true,
		verificationStarted: false,
		keyReceived:         false,
		sasMatched:          make(chan bool, 1),
		hooks:               hooks,
		inRoomID:            inRoomID,
	}
	verState.lock.Lock()
	defer verState.lock.Unlock()

	if !request {
		// start in-room verification
		startEvent, err := mach.SendInRoomSASVerificationStart(ctx, inRoomID, device.UserID, transactionID, hooks.VerificationMethods())
		if err != nil {
			return "", err
		}

		payload, err := json.Marshal(startEvent)
		if err != nil {
			return "", err
		}
		canonical, err := canonicaljson.CanonicalJSON(payload)
		if err != nil {
			return "", err
		}

		verState.startEventCanonical = string(canonical)
	}

	mach.keyVerificationTransactionState.Store(device.UserID.String()+":"+transactionID, verState)

	mach.timeoutAfter(ctx, verState, transactionID, timeout)

	return transactionID, nil
}

func (mach *OlmMachine) handleInRoomVerificationReady(ctx context.Context, userID id.UserID, roomID id.RoomID, content *event.VerificationReadyEventContent, transactionID string) {
	device, err := mach.GetOrFetchDevice(ctx, userID, content.FromDevice)
	if err != nil {
		mach.Log.Error().Msgf("Error fetching device %v of user %v: %v", content.FromDevice, userID, err)
		return
	}

	verState, err := mach.getTransactionState(ctx, transactionID, userID)
	if err != nil {
		mach.Log.Error().Msgf("Error getting transaction state: %v", err)
		return
	}
	//mach.keyVerificationTransactionState.Delete(userID.String() + ":" + transactionID)

	if mach.Client.UserID < userID {
		// up to us to send the start message
		verState.lock.Lock()
		mach.newInRoomSASVerificationWithInner(ctx, roomID, device, verState.hooks, transactionID, 10*time.Minute)
		verState.lock.Unlock()
	}
}
