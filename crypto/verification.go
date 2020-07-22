// Copyright (c) 2020 Nikos Filippakis
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strconv"

	"github.com/pkg/errors"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/canonicaljson"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// ErrUnknownTransaction is returned when a key verification message is received with an unknown transaction ID.
var ErrUnknownTransaction = errors.New("Unknown transaction")

// ErrUnknownVerificationMethod is returned when the verification method in a received m.key.verification.start is unknown.
var ErrUnknownVerificationMethod = errors.New("Unknown verification method")

// sendToOneDevice sends a to-device event to a single device.
func (mach *OlmMachine) sendToOneDevice(userID id.UserID, deviceID id.DeviceID, eventType event.Type, content interface{}) error {
	_, err := mach.Client.SendToDevice(eventType, &mautrix.ReqSendToDevice{
		Messages: map[id.UserID]map[id.DeviceID]*event.Content{
			userID: {
				deviceID: {
					Parsed: content,
				},
			},
		},
	})

	return err
}

// verificationState holds all the information needed for the state of a SAS verification with another device.
type verificationState struct {
	sas           *olm.SAS
	otherDevice   *DeviceIdentity
	initiatedByUs bool
}

// getTransactionState retrieves the given transaction's state, or cancels the transaction if it cannot be found or there is a mismatch.
func (mach *OlmMachine) getTransactionState(transactionID string, userID id.UserID) (*verificationState, error) {
	verStateInterface, ok := mach.keyVerificationTransactionState.Load(transactionID)
	if !ok {
		mach.CancelSASVerification(userID, id.DeviceID("*"), transactionID, "Unknown transaction: "+transactionID, event.VerificationCancelUnknownTransaction)
		return nil, ErrUnknownTransaction
	}
	verState := verStateInterface.(*verificationState)
	if verState.otherDevice.UserID != userID {
		reason := fmt.Sprintf("Unknown user for transaction %v: %v", transactionID, userID)
		mach.CancelSASVerification(userID, id.DeviceID("*"), transactionID, reason, event.VerificationCancelUserMismatch)
		mach.keyVerificationTransactionState.Delete(transactionID)
		return nil, errors.New(reason)
	}
	return verState, nil
}

// handleVerificationStart handles an incoming m.key.verification.start message.
// It initializes the state for this SAS verification process and stores it.
func (mach *OlmMachine) handleVerificationStart(userID id.UserID, content *event.VerificationStartEventContent) {
	mach.Log.Debug("Received verification start from %v", content.FromDevice)
	otherDevice, err := mach.getOrFetchDevice(userID, content.FromDevice)
	if err != nil {
		mach.Log.Error("Could not find device %v of user %v", content.FromDevice, userID)
		return
	}
	verState := &verificationState{
		sas:           olm.NewSAS(),
		otherDevice:   otherDevice,
		initiatedByUs: false,
	}
	if mach.AcceptVerificationFrom(otherDevice) {
		mach.keyVerificationTransactionState.Store(content.TransactionID, verState)
		// TODO cancel transaction on any error
		// TODO start timeout to cancel this transaction
		if err := mach.AcceptSASVerification(userID, content, verState.sas.GetPubkey()); err != nil {
			mach.Log.Error("Error accepting SAS verification: %v", err)
		}
	} else {
		mach.Log.Debug("Not accepting SAS verification %v from %v of user %v", content.TransactionID, otherDevice.DeviceID, otherDevice.UserID)
		if err := mach.CancelSASVerification(
			otherDevice.UserID, otherDevice.DeviceID, content.TransactionID, "Not accepted by user", event.VerificationCancelByUser); err != nil {

			mach.Log.Error("Error canceling SAS verification: %v", err)
		}
	}
}

// handleVerificationAccept handles an incoming m.key.verification.accept message.
// It continues the SAS verification process by sending the SAS key message to the other device.
func (mach *OlmMachine) handleVerificationAccept(userID id.UserID, content *event.VerificationAcceptEventContent) {
	// TODO
}

// handleVerificationKey handles an incoming m.key.verification.key message.
// It stores the other device's public key in order to acquire the SAS shared secret.
// TODO async func for assuring SAS match
func (mach *OlmMachine) handleVerificationKey(userID id.UserID, content *event.VerificationKeyEventContent) {
	mach.Log.Debug("Got verification key for transaction %v: %v", content.TransactionID, content.Key)
	verState, err := mach.getTransactionState(content.TransactionID, userID)
	if err != nil {
		mach.Log.Error("Error getting transaction state: %v", err)
		return
	}
	if err := verState.sas.SetTheirKey([]byte(content.Key)); err != nil {
		mach.Log.Error("Error setting other device's key: %v", err)
		return
	}
	key := verState.sas.GetPubkey()

	// TODO depends on the order of who sent what
	numbers, err := mach.GetSASVerificationNumbers(userID, verState.otherDevice.DeviceID, content.TransactionID, verState.sas)
	if err != nil {
		mach.Log.Error("Error getting SAS verification numbers: %v", err)
		return
	}

	// function provided by the caller to determine if the SAS numbers match
	if !mach.VerifySASNumbersMatch(numbers, verState.otherDevice) {
		mach.Log.Warn("SAS numbers do not match! Canceling transaction %v", content.TransactionID)
		mach.keyVerificationTransactionState.Delete(content.TransactionID)
		mach.CancelSASVerification(userID, verState.otherDevice.DeviceID, content.TransactionID, "Numbers do not match", event.VerificationCancelSASMismatch)
		return
	}

	if err := mach.SendSASVerificationKey(userID, verState.otherDevice.DeviceID, content.TransactionID, string(key)); err != nil {
		mach.Log.Error("Error sending SAS key to other device: %v", err)
	}
}

// handleVerificationMAC handles an incoming m.key.verification.mac message.
// It verifies the other device's MAC and sends our own.
func (mach *OlmMachine) handleVerificationMAC(userID id.UserID, content *event.VerificationMacEventContent) {
	mach.Log.Debug("Got MAC for verification %v: %v, MAC for keys: %v", content.TransactionID, content.Mac, content.Keys)
	verState, err := mach.getTransactionState(content.TransactionID, userID)
	if err != nil {
		mach.Log.Error("Error getting transaction state: %v", err)
		return
	}
	if err := mach.SendSASVerificationMAC(userID, verState.otherDevice.DeviceID, content.TransactionID, verState.sas); err != nil {
		mach.Log.Error("Error sending verification MAC to other device: %v", err)
	}
}

// handleVerificationCancel handles an incoming m.key.verification.cancel message.
// It cancels the verification process for the given reason.
func (mach *OlmMachine) handleVerificationCancel(userID id.UserID, content *event.VerificationCancelEventContent) {
	// make sure to not reply with a cancel to not cause a loop of cancel messages
	// this verification will get canceled even if the senders do not match
	mach.keyVerificationTransactionState.Delete(content.TransactionID)
	mach.Log.Warn("SAS verification %v was canceled by %v with reason: %v (%v)",
		content.TransactionID, userID, content.Reason, content.Code)
}

// handleVerificationRequest handles an incoming m.key.verification.request message.
func (mach *OlmMachine) handleVerificationRequest(userID id.UserID, content *event.VerificationRequestEventContent) {
	mach.Log.Debug("Received verification request from %v", content.FromDevice)
	otherDevice, err := mach.getOrFetchDevice(userID, content.FromDevice)
	if err != nil {
		mach.Log.Error("Could not find device %v of user %v", content.FromDevice, userID)
		return
	}
	if mach.AcceptVerificationFrom(otherDevice) {
		mach.Log.Debug("Accepting SAS verification %v from %v of user %v", content.TransactionID, otherDevice.DeviceID, otherDevice.UserID)
		if err := mach.NewSASVerificationWith(otherDevice, content.TransactionID); err != nil {
			mach.Log.Error("Error accepting SAS verification request: %v", err)
		}
	} else {
		mach.Log.Debug("Not accepting SAS verification %v from %v of user %v", content.TransactionID, otherDevice.DeviceID, otherDevice.UserID)
		if err := mach.CancelSASVerification(
			otherDevice.UserID, otherDevice.DeviceID, content.TransactionID, "Not accepted by user", event.VerificationCancelByUser); err != nil {

			mach.Log.Error("Error canceling SAS verification: %v", err)
		}
	}
}

// NewSASVerificationWith starts the SAS verification process with another device.
// If the transaction ID is empty, a new one is generated.
func (mach *OlmMachine) NewSASVerificationWith(device *DeviceIdentity, transactionID string) error {
	if transactionID == "" {
		transactionID = strconv.Itoa(rand.Int())
	}
	mach.Log.Debug("Starting new verification transaction %v with device %v of user %v", transactionID, device.DeviceID, device.UserID)

	verState := &verificationState{
		sas:           olm.NewSAS(),
		otherDevice:   device,
		initiatedByUs: true,
	}
	mach.keyVerificationTransactionState.Store(transactionID, verState)

	return mach.StartSASVerification(device.UserID, device.DeviceID, transactionID)
}

// StartSASVerification sends the SAS verification start message to another device.
func (mach *OlmMachine) StartSASVerification(toUserID id.UserID, toDeviceID id.DeviceID, transactionID string) error {
	// TODO support emoji verification
	content := &event.VerificationStartEventContent{
		FromDevice:                 mach.Client.DeviceID,
		TransactionID:              transactionID,
		Method:                     event.VerificationMethodSAS,
		KeyAgreementProtocols:      []event.KeyAgreementProtocol{event.KeyAgreementCurve25519},
		Hashes:                     []event.VerificationHashMethod{event.VerificationHashSHA256},
		MessageAuthenticationCodes: []event.MACMethod{event.HKDFHMACSHA256},
		ShortAuthenticationString:  []event.SASMethod{event.SASDecimal},
	}
	return mach.sendToOneDevice(toUserID, toDeviceID, event.ToDeviceVerificationStart, content)
}

// AcceptSASVerification accepts a SAS verification process from a received m.key.verification.start event.
func (mach *OlmMachine) AcceptSASVerification(fromUser id.UserID, startEvent *event.VerificationStartEventContent, publicKey []byte) error {
	if startEvent.Method != event.VerificationMethodSAS {
		reason := "Unknown verification method: " + string(startEvent.Method)
		if err := mach.CancelSASVerification(fromUser, startEvent.FromDevice, startEvent.TransactionID, reason, event.VerificationCancelUnknownMethod); err != nil {
			return err
		}
		return ErrUnknownVerificationMethod
	}
	json, err := json.Marshal(startEvent)
	if err != nil {
		return err
	}
	canonical, err := canonicaljson.CanonicalJSON(json)
	if err != nil {
		return err
	}
	hash := olm.NewUtility().Sha256(string(publicKey) + string(canonical))
	content := &event.VerificationAcceptEventContent{
		TransactionID:             startEvent.TransactionID,
		Method:                    event.VerificationMethodSAS,
		KeyAgreementProtocol:      event.KeyAgreementCurve25519,
		Hash:                      event.VerificationHashSHA256,
		MessageAuthenticationCode: event.HKDFHMACSHA256,
		ShortAuthenticationString: []event.SASMethod{event.SASDecimal},
		Commitment:                hash,
	}
	return mach.sendToOneDevice(fromUser, startEvent.FromDevice, event.ToDeviceVerificationAccept, content)
}

// CancelSASVerification accepts a SAS verification process from a received m.key.verification.start event.
func (mach *OlmMachine) CancelSASVerification(userID id.UserID, deviceID id.DeviceID, transactionID string, reason string, code event.VerificationCancelCode) error {
	content := &event.VerificationCancelEventContent{
		TransactionID: transactionID,
		Reason:        reason,
		Code:          code,
	}
	return mach.sendToOneDevice(userID, deviceID, event.ToDeviceVerificationCancel, content)
}

// SendSASVerificationKey sends the ephemeral public key for a device to the partner device.
func (mach *OlmMachine) SendSASVerificationKey(userID id.UserID, deviceID id.DeviceID, transactionID string, key string) error {
	content := &event.VerificationKeyEventContent{
		TransactionID: transactionID,
		Key:           key,
	}
	return mach.sendToOneDevice(userID, deviceID, event.ToDeviceVerificationKey, content)
}

// GetSASVerificationNumbers generates the three numbers that need to match with the other device for a verification to be valid.
func (mach *OlmMachine) GetSASVerificationNumbers(userID id.UserID, deviceID id.DeviceID, transactionID string, sas *olm.SAS) ([3]uint, error) {
	sasInfo := "MATRIX_KEY_VERIFICATION_SAS" +
		userID.String() + deviceID.String() +
		mach.Client.UserID.String() + mach.Client.DeviceID.String() +
		transactionID

	sasBytes, err := sas.GenerateBytes([]byte(sasInfo))
	if err != nil {
		return [3]uint{0, 0, 0}, err
	}

	numbers := [3]uint{
		(uint(sasBytes[0])<<5 | uint(sasBytes[1])>>3) + 1000,
		(uint(sasBytes[1]&0x7)<<10 | uint(sasBytes[2])<<2 | uint(sasBytes[3]>>6)) + 1000,
		(uint(sasBytes[3]&0x3F)<<7 | uint(sasBytes[4])>>1) + 1000,
	}
	mach.Log.Debug("Generated SAS numbers are: %v-%v-%v", numbers[0], numbers[1], numbers[2])

	return numbers, nil
}

// SendSASVerificationMAC sends the MAC of a device's key to the partner device.
func (mach *OlmMachine) SendSASVerificationMAC(userID id.UserID, deviceID id.DeviceID, transactionID string, sas *olm.SAS) error {
	keyID := id.NewKeyID(id.KeyAlgorithmEd25519, mach.Client.DeviceID.String())

	sasInfo := "MATRIX_KEY_VERIFICATION_MAC" +
		mach.Client.UserID.String() + mach.Client.DeviceID.String() +
		userID.String() + deviceID.String() +
		transactionID
	pubKeyMac, err := sas.CalculateMAC([]byte(mach.account.SigningKey()), []byte(sasInfo+keyID.String()))
	if err != nil {
		return err
	}
	mach.Log.Debug("MAC of key %v is: %v", string(mach.account.SigningKey()), string(pubKeyMac))
	keysMac, err := sas.CalculateMAC([]byte(keyID.String()), []byte(sasInfo+"KEY_IDS"))
	if err != nil {
		return err
	}
	mach.Log.Debug("MAC of key ID(s) %v is: %v", keyID.String(), string(keysMac))
	content := &event.VerificationMacEventContent{
		TransactionID: transactionID,
		Keys:          string(keysMac),
		Mac: map[id.KeyID]string{
			keyID: string(pubKeyMac),
		},
	}
	return mach.sendToOneDevice(userID, deviceID, event.ToDeviceVerificationMAC, content)
}
