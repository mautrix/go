// Copyright (c) 2020 Nikos Filippakis
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"maunium.net/go/mautrix/crypto/canonicaljson"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// ProcessInRoomVerification is a callback that is to be called when a client receives a message
// related to in-room verification.
func (mach *OlmMachine) ProcessInRoomVerification(evt *event.Event, relatesTo *event.RelatesTo) error {
	if evt.Sender == mach.Client.UserID {
		// nothing to do if the message is our own
		return nil
	}
	if relatesTo == nil && evt.Type != event.EventMessage {
		return errors.New("Missing relates_to information")
	}
	switch content := evt.Content.Parsed.(type) {
	case *event.MessageEventContent:
		if content.MsgType == event.MsgVerificationRequest {
			if content.FromDevice == "" {
				return errors.New("from_device field is empty")
			}
			if content.Methods == nil {
				return errors.New("methods field is empty")
			}

			newContent := &event.VerificationRequestEventContent{
				FromDevice:    content.FromDevice,
				Methods:       content.Methods,
				Timestamp:     evt.Timestamp,
				TransactionID: evt.ID.String(),
			}
			mach.handleVerificationRequest(evt.Sender, newContent, evt.ID.String(), evt.RoomID)
		}
	case *event.VerificationStartEventContent:
		mach.handleVerificationStart(evt.Sender, content, relatesTo.EventID.String(), 10*time.Minute, "")
	case *event.VerificationAcceptEventContent:
		mach.handleVerificationAccept(evt.Sender, content, relatesTo.EventID.String())
	case *event.VerificationKeyEventContent:
		mach.handleVerificationKey(evt.Sender, content, relatesTo.EventID.String())
	case *event.VerificationMacEventContent:
		mach.handleVerificationMAC(evt.Sender, content, relatesTo.EventID.String())
	case *event.VerificationCancelEventContent:
		mach.handleVerificationCancel(evt.Sender, content, relatesTo.EventID.String())
	}
	return nil
}

// SendInRoomSASVerificationCancel is used to manually send an in-room SAS cancel message process with the given reason and cancellation code.
func (mach *OlmMachine) SendInRoomSASVerificationCancel(roomID id.RoomID, userID id.UserID, transactionID string, reason string, code event.VerificationCancelCode) error {
	content := &event.VerificationCancelEventContent{
		RelatesTo: event.RelatesTo{Type: event.RelReference, EventID: id.EventID(transactionID)},
		Reason:    reason,
		Code:      code,
		To:        userID,
	}
	_, err := mach.Client.SendMessageEvent(roomID, event.InRoomVerificationCancel, content)
	return err
}

// SendInRoomSASVerificationRequest is used to manually send an in-room SAS verification request message to another user.
func (mach *OlmMachine) SendInRoomSASVerificationRequest(roomID id.RoomID, toUserID id.UserID, methods []VerificationMethod) (string, error) {
	content := &event.MessageEventContent{
		MsgType:    event.MsgVerificationRequest,
		FromDevice: mach.Client.DeviceID,
		Methods:    []event.VerificationMethod{event.VerificationMethodSAS},
		To:         toUserID,
	}

	resp, err := mach.Client.SendMessageEvent(roomID, event.EventMessage, content)
	return resp.EventID.String(), err
}

// SendInRoomSASVerificationStart is used to manually send the in-room SAS verification start message to another user.
func (mach *OlmMachine) SendInRoomSASVerificationStart(roomID id.RoomID, toUserID id.UserID, transactionID string, methods []VerificationMethod) (*event.VerificationStartEventContent, error) {
	sasMethods := make([]event.SASMethod, len(methods))
	for i, method := range methods {
		sasMethods[i] = method.Type()
	}
	content := &event.VerificationStartEventContent{
		FromDevice:                 mach.Client.DeviceID,
		RelatesTo:                  event.RelatesTo{Type: event.RelReference, EventID: id.EventID(transactionID)},
		Method:                     event.VerificationMethodSAS,
		KeyAgreementProtocols:      []event.KeyAgreementProtocol{event.KeyAgreementCurve25519HKDFSHA256},
		Hashes:                     []event.VerificationHashMethod{event.VerificationHashSHA256},
		MessageAuthenticationCodes: []event.MACMethod{event.HKDFHMACSHA256},
		ShortAuthenticationString:  sasMethods,
		To:                         toUserID,
	}

	_, err := mach.Client.SendMessageEvent(roomID, event.InRoomVerificationStart, content)
	return content, err
}

// SendInRoomSASVerificationAccept is used to manually send an accept for an in-room SAS verification process from a received m.key.verification.start event.
func (mach *OlmMachine) SendInRoomSASVerificationAccept(roomID id.RoomID, fromUser id.UserID, startEvent *event.VerificationStartEventContent, publicKey []byte, methods []VerificationMethod) error {
	if startEvent.Method != event.VerificationMethodSAS {
		reason := "Unknown verification method: " + string(startEvent.Method)
		if err := mach.SendInRoomSASVerificationCancel(roomID, fromUser, startEvent.TransactionID, reason, event.VerificationCancelUnknownMethod); err != nil {
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
		RelatesTo:                 event.RelatesTo{Type: event.RelReference, EventID: id.EventID(startEvent.TransactionID)},
		Method:                    event.VerificationMethodSAS,
		KeyAgreementProtocol:      event.KeyAgreementCurve25519HKDFSHA256,
		Hash:                      event.VerificationHashSHA256,
		MessageAuthenticationCode: event.HKDFHMACSHA256,
		ShortAuthenticationString: sasMethods,
		Commitment:                hash,
		To:                        fromUser,
	}
	_, err = mach.Client.SendMessageEvent(roomID, event.InRoomVerificationAccept, content)
	return err
}

// SendInRoomSASVerificationKey sends the ephemeral public key for a device to the partner device for an in-room verification.
func (mach *OlmMachine) SendInRoomSASVerificationKey(roomID id.RoomID, userID id.UserID, transactionID string, key string) error {
	content := &event.VerificationKeyEventContent{
		RelatesTo: event.RelatesTo{Type: event.RelReference, EventID: id.EventID(transactionID)},
		Key:       key,
		To:        userID,
	}
	_, err := mach.Client.SendMessageEvent(roomID, event.InRoomVerificationKey, content)
	return err
}

// SendInRoomSASVerificationMAC sends the MAC of a device's key to the partner device for an in-room verification.
func (mach *OlmMachine) SendInRoomSASVerificationMAC(roomID id.RoomID, userID id.UserID, deviceID id.DeviceID, transactionID string, sas *olm.SAS) error {
	keyID := id.NewKeyID(id.KeyAlgorithmEd25519, mach.Client.DeviceID.String())

	signingKey := mach.account.SigningKey()
	keyIDsMap := map[id.KeyID]string{keyID: ""}
	macMap := make(map[id.KeyID]string)

	if mach.crossSigningKeys != nil {
		masterKey := mach.crossSigningKeys.MasterKey.PublicKey
		masterKeyID := id.NewKeyID(id.KeyAlgorithmEd25519, masterKey.String())
		// add master key ID to key map
		keyIDsMap[masterKeyID] = ""
		masterKeyMAC, _, err := mach.getPKAndKeysMAC(sas, mach.Client.UserID, mach.Client.DeviceID,
			userID, deviceID, transactionID, masterKey, masterKeyID, keyIDsMap)
		if err != nil {
			mach.Log.Error("Error generating master key MAC: %v", err)
		} else {
			mach.Log.Debug("Generated master key `%v` MAC: %v", masterKey, masterKeyMAC)
			macMap[masterKeyID] = masterKeyMAC
		}
	}

	pubKeyMac, keysMac, err := mach.getPKAndKeysMAC(sas, mach.Client.UserID, mach.Client.DeviceID, userID, deviceID, transactionID, signingKey, keyID, keyIDsMap)
	if err != nil {
		return err
	}
	mach.Log.Debug("MAC of key %s is: %s", signingKey, pubKeyMac)
	mach.Log.Debug("MAC of key ID(s) %s is: %s", keyID, keysMac)
	macMap[keyID] = pubKeyMac

	content := &event.VerificationMacEventContent{
		RelatesTo: event.RelatesTo{Type: event.RelReference, EventID: id.EventID(transactionID)},
		Keys:      keysMac,
		Mac:       macMap,
		To:        userID,
	}

	_, err = mach.Client.SendMessageEvent(roomID, event.InRoomVerificationMAC, content)
	return err
}
