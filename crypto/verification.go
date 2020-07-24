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

func getPKAndKeysMAC(sas *olm.SAS, sendingUser id.UserID, sendingDevice id.DeviceID, receivingUser id.UserID, receivingDevice id.DeviceID,
	transactionID string, signingKey string, keyID id.KeyID) ([]byte, []byte, error) {
	sasInfo := "MATRIX_KEY_VERIFICATION_MAC" +
		sendingUser.String() + sendingDevice.String() +
		receivingUser.String() + receivingDevice.String() +
		transactionID
	pubKeyMac, err := sas.CalculateMAC([]byte(signingKey), []byte(sasInfo+keyID.String()))
	if err != nil {
		return nil, nil, err
	}
	keysMac, err := sas.CalculateMAC([]byte(keyID.String()), []byte(sasInfo+"KEY_IDS"))
	if err != nil {
		return nil, nil, err
	}
	return pubKeyMac, keysMac, nil
}

// verificationState holds all the information needed for the state of a SAS verification with another device.
type verificationState struct {
	sas                 *olm.SAS
	otherDevice         *DeviceIdentity
	initiatedByUs       bool
	verificationStarted bool
	keyReceived         bool
	sasMatched          bool
	commitment          string
	startEventCanonical string
}

// getTransactionState retrieves the given transaction's state, or cancels the transaction if it cannot be found or there is a mismatch.
func (mach *OlmMachine) getTransactionState(transactionID string, userID id.UserID) (*verificationState, error) {
	verStateInterface, ok := mach.keyVerificationTransactionState.Load(userID.String() + ":" + transactionID)
	if !ok {
		mach.CancelSASVerification(userID, id.DeviceID("*"), transactionID, "Unknown transaction: "+transactionID, event.VerificationCancelUnknownTransaction)
		return nil, ErrUnknownTransaction
	}
	verState := verStateInterface.(*verificationState)
	if verState.otherDevice.UserID != userID {
		reason := fmt.Sprintf("Unknown user for transaction %v: %v", transactionID, userID)
		mach.CancelSASVerification(userID, id.DeviceID("*"), transactionID, reason, event.VerificationCancelUserMismatch)
		mach.keyVerificationTransactionState.Delete(userID.String() + ":" + transactionID)
		return nil, errors.New(reason)
	}
	return verState, nil
}

// TODO emojis
// TODO key forwarding to now consider only trusted devices test

// handleVerificationStart handles an incoming m.key.verification.start message.
// It initializes the state for this SAS verification process and stores it.
func (mach *OlmMachine) handleVerificationStart(userID id.UserID, content *event.VerificationStartEventContent) {
	mach.Log.Debug("Received verification start from %v", content.FromDevice)
	otherDevice, err := mach.GetOrFetchDevice(userID, content.FromDevice)
	if err != nil {
		mach.Log.Error("Could not find device %v of user %v", content.FromDevice, userID)
		return
	}
	if content.Method != event.VerificationMethodSAS {
		mach.Log.Warn("Canceling verification transaction %v as it is not SAS", content.TransactionID)
		mach.CancelSASVerification(otherDevice.UserID, otherDevice.DeviceID, content.TransactionID, "Only SAS method is supported", event.VerificationCancelUnknownMethod)
		return
	}
	// check for curve25519
	hasCurve := false
	for _, prot := range content.KeyAgreementProtocols {
		if prot == event.KeyAgreementCurve25519 {
			hasCurve = true
			break
		}
	}
	if !hasCurve {
		mach.Log.Warn("Canceling verification transaction %v as it does not support Curve25519 key agreement protocol", content.TransactionID)
		mach.CancelSASVerification(otherDevice.UserID, otherDevice.DeviceID, content.TransactionID, "Only Curve25519 key agreement protocol is supported", event.VerificationCancelUnknownMethod)
		return
	}
	// check for sha256
	hasSHA := false
	for _, hash := range content.Hashes {
		if hash == event.VerificationHashSHA256 {
			hasSHA = true
			break
		}
	}
	if !hasSHA {
		mach.Log.Warn("Canceling verification transaction %v as it does not support SHA256 hashing", content.TransactionID)
		mach.CancelSASVerification(otherDevice.UserID, otherDevice.DeviceID, content.TransactionID, "Only SHA256 hashing is supported", event.VerificationCancelUnknownMethod)
		return
	}
	// check for HKDF method
	hasHKDF := false
	for _, mac := range content.MessageAuthenticationCodes {
		if mac == event.HKDFHMACSHA256 {
			hasHKDF = true
			break
		}
	}
	if !hasHKDF {
		mach.Log.Warn("Canceling verification transaction %v as it does not support MAC method hkdf-hmac-sha256", content.TransactionID)
		mach.CancelSASVerification(otherDevice.UserID, otherDevice.DeviceID, content.TransactionID, "Only hkdf-hmac-sha256 mac method is supported", event.VerificationCancelUnknownMethod)
		return
	}
	// check for SAS method
	hasDecimal := false
	for _, sas := range content.ShortAuthenticationString {
		if sas == event.SASDecimal {
			hasDecimal = true
		}
	}
	if !hasDecimal {
		mach.Log.Warn("Canceling verification transaction %v as it does not support decimal SAS", content.TransactionID)
		mach.CancelSASVerification(otherDevice.UserID, otherDevice.DeviceID, content.TransactionID, "Decimal SAS method must be supported", event.VerificationCancelUnknownMethod)
		return
	}

	if mach.AcceptVerificationFrom(otherDevice) {
		verState := &verificationState{
			sas:                 olm.NewSAS(),
			otherDevice:         otherDevice,
			initiatedByUs:       false,
			verificationStarted: true,
			keyReceived:         false,
			sasMatched:          false,
		}
		_, loaded := mach.keyVerificationTransactionState.LoadOrStore(userID.String()+":"+content.TransactionID, verState)
		if loaded {
			// transaction already exists
			mach.Log.Error("Transaction %v already exists, canceling", content.TransactionID)
			mach.CancelSASVerification(otherDevice.UserID, otherDevice.DeviceID, content.TransactionID, "Transaction already exists", event.VerificationCancelUnexpectedMessage)
			return
		}
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
	mach.Log.Debug("Received verification accept for transaction %v", content.TransactionID)
	verState, err := mach.getTransactionState(content.TransactionID, userID)
	if err != nil {
		mach.Log.Error("Error getting transaction state: %v", err)
		return
	}

	if !verState.initiatedByUs || verState.verificationStarted {
		// unexpected accept at this point
		mach.Log.Warn("Unexpected verification accept message for transaction %v", content.TransactionID)
		mach.keyVerificationTransactionState.Delete(userID.String() + ":" + content.TransactionID)
		mach.CancelSASVerification(verState.otherDevice.UserID, verState.otherDevice.DeviceID, content.TransactionID, "Unexpected accept message", event.VerificationCancelUnexpectedMessage)
		return
	}

	hasDecimal := false
	for _, sas := range content.ShortAuthenticationString {
		if sas == event.SASDecimal {
			hasDecimal = true
		}
	}

	if content.KeyAgreementProtocol != event.KeyAgreementCurve25519 ||
		content.Hash != event.VerificationHashSHA256 ||
		content.MessageAuthenticationCode != event.HKDFHMACSHA256 ||
		!hasDecimal {

		mach.Log.Warn("Canceling verification transaction %v due to unknown parameter", content.TransactionID)
		mach.keyVerificationTransactionState.Delete(userID.String() + ":" + content.TransactionID)
		mach.CancelSASVerification(verState.otherDevice.UserID, verState.otherDevice.DeviceID, content.TransactionID, "Verification uses unknown method", event.VerificationCancelUnknownMethod)
		return
	}

	key := verState.sas.GetPubkey()
	verState.commitment = content.Commitment
	verState.verificationStarted = true
	if err := mach.SendSASVerificationKey(userID, verState.otherDevice.DeviceID, content.TransactionID, string(key)); err != nil {
		mach.Log.Error("Error sending SAS key to other device: %v", err)
		return
	}
}

// handleVerificationKey handles an incoming m.key.verification.key message.
// It stores the other device's public key in order to acquire the SAS shared secret.
func (mach *OlmMachine) handleVerificationKey(userID id.UserID, content *event.VerificationKeyEventContent) {
	transactionID := content.TransactionID
	mach.Log.Debug("Got verification key for transaction %v: %v", transactionID, content.Key)
	verState, err := mach.getTransactionState(transactionID, userID)
	if err != nil {
		mach.Log.Error("Error getting transaction state: %v", err)
		return
	}

	if !verState.verificationStarted || verState.keyReceived {
		// unexpected key at this point
		mach.Log.Warn("Unexpected verification key message for transaction %v", content.TransactionID)
		mach.keyVerificationTransactionState.Delete(userID.String() + ":" + content.TransactionID)
		mach.CancelSASVerification(verState.otherDevice.UserID, verState.otherDevice.DeviceID, content.TransactionID, "Unexpected key message", event.VerificationCancelUnexpectedMessage)
		return
	}

	if err := verState.sas.SetTheirKey([]byte(content.Key)); err != nil {
		mach.Log.Error("Error setting other device's key: %v", err)
		return
	}

	verState.keyReceived = true

	if verState.initiatedByUs {
		// verify commitment string from accept message now
		expectedCommitment := olm.NewUtility().Sha256(content.Key + verState.startEventCanonical)
		mach.Log.Debug("Received commitment: %v Expected: %v", verState.commitment, expectedCommitment)
		if expectedCommitment != verState.commitment {
			mach.Log.Warn("Canceling verification transaction %v due to commitment mismatch", transactionID)
			mach.keyVerificationTransactionState.Delete(userID.String() + ":" + transactionID)
			mach.CancelSASVerification(verState.otherDevice.UserID, verState.otherDevice.DeviceID, transactionID, "Commitment mismatch", event.VerificationCancelCommitmentMismatch)
			return
		}
	} else {
		// if verification was initiated by other device, send out our key now
		key := verState.sas.GetPubkey()
		if err := mach.SendSASVerificationKey(userID, verState.otherDevice.DeviceID, transactionID, string(key)); err != nil {
			mach.Log.Error("Error sending SAS key to other device: %v", err)
			return
		}
	}

	// compare the SAS keys and send out the MAC
	numbers, err := mach.GetSASVerificationNumbers(userID, verState.otherDevice.DeviceID, transactionID, verState.sas)
	if err != nil {
		mach.Log.Error("Error getting SAS verification numbers: %v", err)
		return
	}

	go mach.verifySASMatch(numbers, transactionID, verState)
}

// verifySASMatch is called asynchronously. It waits for the SAS to be compared for the verification to proceed.
// If the SAS match, then our MAC is sent out. Otherwise the transaction is canceled.
func (mach *OlmMachine) verifySASMatch(numbers [3]uint, transactionID string, verState *verificationState) {
	// function provided by the caller to determine if the SAS numbers match
	if mach.VerifySASNumbersMatch(numbers, verState.otherDevice) {
		verState.sasMatched = true
		if err := mach.SendSASVerificationMAC(verState.otherDevice.UserID, verState.otherDevice.DeviceID, transactionID, verState.sas); err != nil {
			mach.Log.Error("Error sending verification MAC to other device: %v", err)
		}
	} else {
		mach.Log.Warn("SAS numbers do not match! Canceling transaction %v", transactionID)
		mach.keyVerificationTransactionState.Delete(verState.otherDevice.UserID.String() + ":" + transactionID)
		mach.CancelSASVerification(verState.otherDevice.UserID, verState.otherDevice.DeviceID, transactionID, "Numbers do not match", event.VerificationCancelSASMismatch)
	}
}

// handleVerificationMAC handles an incoming m.key.verification.mac message.
// It verifies the other device's MAC and if the MAC is valid it marks the device as trusted.
func (mach *OlmMachine) handleVerificationMAC(userID id.UserID, content *event.VerificationMacEventContent) {
	mach.Log.Debug("Got MAC for verification %v: %v, MAC for keys: %v", content.TransactionID, content.Mac, content.Keys)
	verState, err := mach.getTransactionState(content.TransactionID, userID)
	if err != nil {
		mach.Log.Error("Error getting transaction state: %v", err)
		return
	}

	device := verState.otherDevice

	if !verState.verificationStarted || !verState.keyReceived || !verState.sasMatched {
		// unexpected MAC at this point
		mach.Log.Warn("Unexpected MAC message for transaction %v", content.TransactionID)
		mach.keyVerificationTransactionState.Delete(userID.String() + ":" + content.TransactionID)
		mach.CancelSASVerification(verState.otherDevice.UserID, verState.otherDevice.DeviceID, content.TransactionID, "Unexpected MAC message", event.VerificationCancelUnexpectedMessage)
		return
	}

	// we are done with this SAS verification in all cases so we forget about it
	mach.keyVerificationTransactionState.Delete(userID.String() + ":" + content.TransactionID)

	keyID := id.NewKeyID(id.KeyAlgorithmEd25519, device.DeviceID.String())
	expectedPKMAC, expectedKeysMAC, err := getPKAndKeysMAC(verState.sas, device.UserID, device.DeviceID,
		mach.Client.UserID, mach.Client.DeviceID, content.TransactionID, device.SigningKey.String(), keyID)
	if err != nil {
		mach.Log.Error("Error generating MAC to match with received MAC: %v", err)
		return
	}

	mach.Log.Debug("Expected %v keys MAC, got %v", string(expectedKeysMAC), content.Keys)
	if content.Keys != string(expectedKeysMAC) {
		mach.Log.Warn("Canceling verification transaction %v due to mismatched keys MAC")
		mach.CancelSASVerification(userID, device.DeviceID, content.TransactionID, "Mismatched keys MACs", event.VerificationCancelKeyMismatch)
		return
	}

	mach.Log.Debug("Expected %v PK MAC, got %v", string(expectedPKMAC), content.Mac[keyID])
	if content.Mac[keyID] != string(expectedPKMAC) {
		mach.Log.Warn("Canceling verification transaction %v due to mismatched PK MAC")
		mach.CancelSASVerification(userID, device.DeviceID, content.TransactionID, "Mismatched PK MACs", event.VerificationCancelKeyMismatch)
		return
	}

	// we can finally trust this device
	device.Trust = TrustStateVerified
	mach.CryptoStore.PutDevice(device.UserID, device)

	mach.Log.Debug("Device %v of user %v verified successfully!", device.DeviceID, device.UserID)
}

// handleVerificationCancel handles an incoming m.key.verification.cancel message.
// It cancels the verification process for the given reason.
func (mach *OlmMachine) handleVerificationCancel(userID id.UserID, content *event.VerificationCancelEventContent) {
	// make sure to not reply with a cancel to not cause a loop of cancel messages
	// this verification will get canceled even if the senders do not match
	mach.keyVerificationTransactionState.Delete(userID.String() + ":" + content.TransactionID)
	mach.Log.Warn("SAS verification %v was canceled by %v with reason: %v (%v)",
		content.TransactionID, userID, content.Reason, content.Code)
}

// handleVerificationRequest handles an incoming m.key.verification.request message.
func (mach *OlmMachine) handleVerificationRequest(userID id.UserID, content *event.VerificationRequestEventContent) {
	mach.Log.Debug("Received verification request from %v", content.FromDevice)
	otherDevice, err := mach.GetOrFetchDevice(userID, content.FromDevice)
	if err != nil {
		mach.Log.Error("Could not find device %v of user %v", content.FromDevice, userID)
		return
	}
	// check if SAS is in supported methods
	supportsSAS := false
	for _, method := range content.Methods {
		if method == event.VerificationMethodSAS {
			supportsSAS = true
			break
		}
	}
	if !supportsSAS {
		mach.Log.Warn("Canceling verification transaction %v as SAS is not supported", content.TransactionID)
		mach.CancelSASVerification(otherDevice.UserID, otherDevice.DeviceID, content.TransactionID, "Only SAS method is supported", event.VerificationCancelUnknownMethod)
		return
	}
	if mach.AcceptVerificationFrom(otherDevice) {
		mach.Log.Debug("Accepting SAS verification %v from %v of user %v", content.TransactionID, otherDevice.DeviceID, otherDevice.UserID)
		if err := mach.NewSASVerificationWith(otherDevice, content.TransactionID); err != nil {
			mach.Log.Error("Error accepting SAS verification request: %v", err)
		}
	} else {
		mach.Log.Debug("Not accepting SAS verification %v from %v of user %v", content.TransactionID, otherDevice.DeviceID, otherDevice.UserID)
		mach.CancelSASVerification(otherDevice.UserID, otherDevice.DeviceID, content.TransactionID, "Not accepted by user", event.VerificationCancelByUser)
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
		sas:                 olm.NewSAS(),
		otherDevice:         device,
		initiatedByUs:       true,
		verificationStarted: false,
		keyReceived:         false,
		sasMatched:          false,
	}

	startEvent, err := mach.StartSASVerification(device.UserID, device.DeviceID, transactionID)
	if err != nil {
		return err
	}

	json, err := json.Marshal(startEvent)
	if err != nil {
		return err
	}
	canonical, err := canonicaljson.CanonicalJSON(json)
	if err != nil {
		return err
	}

	verState.startEventCanonical = string(canonical)
	_, loaded := mach.keyVerificationTransactionState.LoadOrStore(device.UserID.String()+":"+transactionID, verState)
	if loaded {
		return errors.New("Transaction already exists")
	}

	return nil
}

// StartSASVerification sends the SAS verification start message to another device.
func (mach *OlmMachine) StartSASVerification(toUserID id.UserID, toDeviceID id.DeviceID, transactionID string) (*event.VerificationStartEventContent, error) {
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
	return content, mach.sendToOneDevice(toUserID, toDeviceID, event.ToDeviceVerificationStart, content)
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

	signingKey := mach.account.SigningKey().String()
	pubKeyMac, keysMac, err := getPKAndKeysMAC(sas, mach.Client.UserID, mach.Client.DeviceID, userID, deviceID, transactionID, signingKey, keyID)
	if err != nil {
		return err
	}
	mach.Log.Debug("MAC of key %v is: %v", string(signingKey), string(pubKeyMac))
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
