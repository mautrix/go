// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package verificationhelper_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/cryptohelper"
	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

var userID = id.UserID("@alice:example.org")
var sendingDeviceID = id.DeviceID("sending")
var receivingDeviceID = id.DeviceID("receiving")

func init() {
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).With().Timestamp().Logger().Level(zerolog.TraceLevel)
	zerolog.DefaultContextLogger = &log.Logger
}

func initServerAndLogin(t *testing.T, ctx context.Context) (ts *mockServer, sendingClient, receivingClient *mautrix.Client, sendingCryptoStore, receivingCryptoStore crypto.Store, sendingMachine, receivingMachine *crypto.OlmMachine) {
	t.Helper()
	ts = createMockServer(t)

	sendingClient, sendingCryptoStore = ts.Login(t, ctx, userID, sendingDeviceID)
	sendingMachine = sendingClient.Crypto.(*cryptohelper.CryptoHelper).Machine()
	receivingClient, receivingCryptoStore = ts.Login(t, ctx, userID, receivingDeviceID)
	receivingMachine = receivingClient.Crypto.(*cryptohelper.CryptoHelper).Machine()

	err := sendingCryptoStore.PutDevice(ctx, userID, sendingMachine.OwnIdentity())
	require.NoError(t, err)
	err = sendingCryptoStore.PutDevice(ctx, userID, receivingMachine.OwnIdentity())
	require.NoError(t, err)
	err = receivingCryptoStore.PutDevice(ctx, userID, sendingMachine.OwnIdentity())
	require.NoError(t, err)
	err = receivingCryptoStore.PutDevice(ctx, userID, receivingMachine.OwnIdentity())
	require.NoError(t, err)
	return
}

func initDefaultCallbacks(t *testing.T, ctx context.Context, sendingClient, receivingClient *mautrix.Client, sendingMachine, receivingMachine *crypto.OlmMachine) (sendingCallbacks, receivingCallbacks *allVerificationCallbacks, sendingHelper, receivingHelper *verificationhelper.VerificationHelper) {
	t.Helper()
	sendingCallbacks = newAllVerificationCallbacks()
	sendingHelper = verificationhelper.NewVerificationHelper(sendingClient, sendingMachine, sendingCallbacks, true)
	require.NoError(t, sendingHelper.Init(ctx))

	receivingCallbacks = newAllVerificationCallbacks()
	receivingHelper = verificationhelper.NewVerificationHelper(receivingClient, receivingMachine, receivingCallbacks, true)
	require.NoError(t, receivingHelper.Init(ctx))
	return
}

func TestSelfVerification_Start(t *testing.T) {
	ctx := log.Logger.WithContext(context.TODO())
	receivingDeviceID2 := id.DeviceID("receiving2")

	testCases := []struct {
		supportsScan                bool
		callbacks                   MockVerificationCallbacks
		startVerificationErrMsg     string
		expectedVerificationMethods []event.VerificationMethod
	}{
		{false, newBaseVerificationCallbacks(), "no supported verification methods", nil},
		{true, newBaseVerificationCallbacks(), "", []event.VerificationMethod{event.VerificationMethodQRCodeScan, event.VerificationMethodReciprocate}},
		{false, newSASVerificationCallbacks(), "", []event.VerificationMethod{event.VerificationMethodSAS}},
		{true, newSASVerificationCallbacks(), "", []event.VerificationMethod{event.VerificationMethodQRCodeScan, event.VerificationMethodReciprocate, event.VerificationMethodSAS}},
		{true, newQRCodeVerificationCallbacks(), "", []event.VerificationMethod{event.VerificationMethodQRCodeScan, event.VerificationMethodQRCodeShow, event.VerificationMethodReciprocate}},
		{false, newQRCodeVerificationCallbacks(), "", []event.VerificationMethod{event.VerificationMethodQRCodeShow, event.VerificationMethodReciprocate}},
		{false, newAllVerificationCallbacks(), "", []event.VerificationMethod{event.VerificationMethodQRCodeShow, event.VerificationMethodReciprocate, event.VerificationMethodSAS}},
		{true, newAllVerificationCallbacks(), "", []event.VerificationMethod{event.VerificationMethodQRCodeScan, event.VerificationMethodQRCodeShow, event.VerificationMethodReciprocate, event.VerificationMethodSAS}},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			ts := createMockServer(t)
			defer ts.Close()

			client, cryptoStore := ts.Login(t, ctx, userID, sendingDeviceID)
			addDeviceID(ctx, cryptoStore, userID, sendingDeviceID)
			addDeviceID(ctx, cryptoStore, userID, receivingDeviceID)
			addDeviceID(ctx, cryptoStore, userID, receivingDeviceID2)

			senderHelper := verificationhelper.NewVerificationHelper(client, client.Crypto.(*cryptohelper.CryptoHelper).Machine(), tc.callbacks, tc.supportsScan)
			err := senderHelper.Init(ctx)
			require.NoError(t, err)

			txnID, err := senderHelper.StartVerification(ctx, userID)
			if tc.startVerificationErrMsg != "" {
				assert.ErrorContains(t, err, tc.startVerificationErrMsg)
				return
			}

			assert.NoError(t, err)
			assert.NotEmpty(t, txnID)

			toDeviceInbox := ts.DeviceInbox[userID]

			// Ensure that we didn't send a verification request to the
			// sending device.
			assert.Empty(t, toDeviceInbox[sendingDeviceID])

			// Ensure that the verification request was sent to both of
			// the other devices.
			assert.NotEmpty(t, toDeviceInbox[receivingDeviceID])
			assert.NotEmpty(t, toDeviceInbox[receivingDeviceID2])
			assert.Equal(t, toDeviceInbox[receivingDeviceID], toDeviceInbox[receivingDeviceID2])
			assert.Len(t, toDeviceInbox[receivingDeviceID], 1)

			// Ensure that the verification request is correct.
			verificationRequest := toDeviceInbox[receivingDeviceID][0].Content.AsVerificationRequest()
			assert.Equal(t, sendingDeviceID, verificationRequest.FromDevice)
			assert.Equal(t, txnID, verificationRequest.TransactionID)
			assert.ElementsMatch(t, tc.expectedVerificationMethods, verificationRequest.Methods)
		})
	}
}

func TestSelfVerification_Accept_NoSupportedMethods(t *testing.T) {
	ctx := log.Logger.WithContext(context.TODO())

	ts := createMockServer(t)
	defer ts.Close()

	sendingClient, sendingCryptoStore := ts.Login(t, ctx, userID, sendingDeviceID)
	receivingClient, _ := ts.Login(t, ctx, userID, receivingDeviceID)
	addDeviceID(ctx, sendingCryptoStore, userID, sendingDeviceID)
	addDeviceID(ctx, sendingCryptoStore, userID, receivingDeviceID)

	sendingMachine := sendingClient.Crypto.(*cryptohelper.CryptoHelper).Machine()
	recoveryKey, cache, err := sendingMachine.GenerateAndUploadCrossSigningKeys(ctx, nil, "")
	assert.NoError(t, err)
	assert.NotEmpty(t, recoveryKey)
	assert.NotNil(t, cache)

	sendingHelper := verificationhelper.NewVerificationHelper(sendingClient, sendingMachine, newAllVerificationCallbacks(), true)
	err = sendingHelper.Init(ctx)
	require.NoError(t, err)

	receivingCallbacks := newBaseVerificationCallbacks()
	receivingHelper := verificationhelper.NewVerificationHelper(receivingClient, receivingClient.Crypto.(*cryptohelper.CryptoHelper).Machine(), receivingCallbacks, false)
	err = receivingHelper.Init(ctx)
	require.NoError(t, err)

	txnID, err := sendingHelper.StartVerification(ctx, userID)
	require.NoError(t, err)
	require.NotEmpty(t, txnID)

	ts.dispatchToDevice(t, ctx, receivingClient)

	// Ensure that the receiver ignored the request because it
	// doesn't support any of the verification methods in the
	// request.
	assert.Empty(t, receivingCallbacks.GetRequestedVerifications())
}

func TestSelfVerification_Accept_CorrectMethodsPresented(t *testing.T) {
	ctx := log.Logger.WithContext(context.TODO())

	testCases := []struct {
		sendingSupportsScan         bool
		receivingSupportsScan       bool
		sendingCallbacks            MockVerificationCallbacks
		receivingCallbacks          MockVerificationCallbacks
		expectedVerificationMethods []event.VerificationMethod
	}{
		{false, false, newSASVerificationCallbacks(), newSASVerificationCallbacks(), []event.VerificationMethod{event.VerificationMethodSAS}},
		{true, false, newQRCodeVerificationCallbacks(), newQRCodeVerificationCallbacks(), []event.VerificationMethod{event.VerificationMethodQRCodeShow, event.VerificationMethodReciprocate}},
		{false, true, newQRCodeVerificationCallbacks(), newQRCodeVerificationCallbacks(), []event.VerificationMethod{event.VerificationMethodQRCodeScan, event.VerificationMethodReciprocate}},
		{true, false, newAllVerificationCallbacks(), newAllVerificationCallbacks(), []event.VerificationMethod{event.VerificationMethodQRCodeShow, event.VerificationMethodReciprocate, event.VerificationMethodSAS}},
		{true, true, newAllVerificationCallbacks(), newAllVerificationCallbacks(), []event.VerificationMethod{event.VerificationMethodQRCodeShow, event.VerificationMethodQRCodeScan, event.VerificationMethodReciprocate, event.VerificationMethodSAS}},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			ts, sendingClient, receivingClient, _, _, sendingMachine, receivingMachine := initServerAndLogin(t, ctx)
			defer ts.Close()

			recoveryKey, sendingCrossSigningKeysCache, err := sendingMachine.GenerateAndUploadCrossSigningKeys(ctx, nil, "")
			assert.NoError(t, err)
			assert.NotEmpty(t, recoveryKey)
			assert.NotNil(t, sendingCrossSigningKeysCache)

			sendingHelper := verificationhelper.NewVerificationHelper(sendingClient, sendingMachine, tc.sendingCallbacks, tc.sendingSupportsScan)
			err = sendingHelper.Init(ctx)
			require.NoError(t, err)

			receivingHelper := verificationhelper.NewVerificationHelper(receivingClient, receivingMachine, tc.receivingCallbacks, tc.receivingSupportsScan)
			err = receivingHelper.Init(ctx)
			require.NoError(t, err)

			txnID, err := sendingHelper.StartVerification(ctx, userID)
			require.NoError(t, err)

			// Process the verification request on the receiving device.
			ts.dispatchToDevice(t, ctx, receivingClient)

			// Ensure that the receiving device received a verification
			// request with the correct transaction ID.
			assert.ElementsMatch(t, []id.VerificationTransactionID{txnID}, tc.receivingCallbacks.GetRequestedVerifications()[userID])

			// Have the receiving device accept the verification request.
			err = receivingHelper.AcceptVerification(ctx, txnID)
			require.NoError(t, err)

			_, sendingIsQRCallbacks := tc.sendingCallbacks.(*qrCodeVerificationCallbacks)
			_, sendingIsAllCallbacks := tc.sendingCallbacks.(*allVerificationCallbacks)
			sendingCanShowQR := sendingIsQRCallbacks || sendingIsAllCallbacks
			_, receivingIsQRCallbacks := tc.receivingCallbacks.(*qrCodeVerificationCallbacks)
			_, receivingIsAllCallbacks := tc.receivingCallbacks.(*allVerificationCallbacks)
			receivingCanShowQR := receivingIsQRCallbacks || receivingIsAllCallbacks

			// Ensure that if the receiving device should show a QR code that
			// it has the correct content.
			if tc.sendingSupportsScan && receivingCanShowQR {
				receivingShownQRCode := tc.receivingCallbacks.GetQRCodeShown(txnID)
				require.NotNil(t, receivingShownQRCode)
				assert.Equal(t, txnID, receivingShownQRCode.TransactionID)
				assert.NotEmpty(t, receivingShownQRCode.SharedSecret)
			}

			// Check for whether the receiving device should be scanning a QR
			// code.
			if tc.receivingSupportsScan && sendingCanShowQR {
				assert.Contains(t, tc.receivingCallbacks.GetScanQRCodeTransactions(), txnID)
			}

			// Check that the m.key.verification.ready event has the correct
			// content.
			sendingInbox := ts.DeviceInbox[userID][sendingDeviceID]
			assert.Len(t, sendingInbox, 1)
			readyEvt := sendingInbox[0].Content.AsVerificationReady()
			assert.Equal(t, txnID, readyEvt.TransactionID)
			assert.Equal(t, receivingDeviceID, readyEvt.FromDevice)
			assert.ElementsMatch(t, tc.expectedVerificationMethods, readyEvt.Methods)

			// Receive the m.key.verification.ready event on the sending
			// device.
			ts.dispatchToDevice(t, ctx, sendingClient)

			// Ensure that if the sending device should show a QR code that it
			// has the correct content.
			if tc.receivingSupportsScan && sendingCanShowQR {
				sendingShownQRCode := tc.sendingCallbacks.GetQRCodeShown(txnID)
				require.NotNil(t, sendingShownQRCode)
				assert.Equal(t, txnID, sendingShownQRCode.TransactionID)
				assert.NotEmpty(t, sendingShownQRCode.SharedSecret)
			}

			// Check for whether the sending device should be scanning a QR
			// code.
			if tc.sendingSupportsScan && receivingCanShowQR {
				assert.Contains(t, tc.sendingCallbacks.GetScanQRCodeTransactions(), txnID)
			}
		})
	}
}

func TestSelfVerification_Accept_QRContents(t *testing.T) {
	ctx := log.Logger.WithContext(context.TODO())

	testCases := []struct {
		sendingGeneratedCrossSigningKeys   bool
		receivingGeneratedCrossSigningKeys bool
		expectedAcceptError                string
	}{
		{true, false, ""},
		{false, true, ""},
		{false, false, "failed to get own cross-signing master public key"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("sendingGenerated=%t receivingGenerated=%t err=%s", tc.sendingGeneratedCrossSigningKeys, tc.receivingGeneratedCrossSigningKeys, tc.expectedAcceptError), func(t *testing.T) {
			ts, sendingClient, receivingClient, _, _, sendingMachine, receivingMachine := initServerAndLogin(t, ctx)
			defer ts.Close()
			sendingCallbacks, receivingCallbacks, sendingHelper, receivingHelper := initDefaultCallbacks(t, ctx, sendingClient, receivingClient, sendingMachine, receivingMachine)
			var err error

			var sendingRecoveryKey, receivingRecoveryKey string
			var sendingCrossSigningKeysCache, receivingCrossSigningKeysCache *crypto.CrossSigningKeysCache

			if tc.sendingGeneratedCrossSigningKeys {
				sendingRecoveryKey, sendingCrossSigningKeysCache, err = sendingMachine.GenerateAndUploadCrossSigningKeys(ctx, nil, "")
				require.NoError(t, err)
				assert.NotEmpty(t, sendingRecoveryKey)
				assert.NotNil(t, sendingCrossSigningKeysCache)
			}

			if tc.receivingGeneratedCrossSigningKeys {
				receivingRecoveryKey, receivingCrossSigningKeysCache, err = receivingMachine.GenerateAndUploadCrossSigningKeys(ctx, nil, "")
				require.NoError(t, err)
				assert.NotEmpty(t, receivingRecoveryKey)
				assert.NotNil(t, receivingCrossSigningKeysCache)
			}

			// Send the verification request from the sender device and accept
			// it on the receiving device and receive the verification ready
			// event on the sending device.
			txnID, err := sendingHelper.StartVerification(ctx, userID)
			require.NoError(t, err)
			ts.dispatchToDevice(t, ctx, receivingClient)

			err = receivingHelper.AcceptVerification(ctx, txnID)
			if tc.expectedAcceptError != "" {
				assert.ErrorContains(t, err, tc.expectedAcceptError)
				return
			} else {
				require.NoError(t, err)
			}

			ts.dispatchToDevice(t, ctx, sendingClient)

			receivingShownQRCode := receivingCallbacks.GetQRCodeShown(txnID)
			require.NotNil(t, receivingShownQRCode)
			assert.NotEmpty(t, receivingShownQRCode.SharedSecret)
			assert.Equal(t, txnID, receivingShownQRCode.TransactionID)

			sendingShownQRCode := sendingCallbacks.GetQRCodeShown(txnID)
			require.NotNil(t, sendingShownQRCode)
			assert.NotEmpty(t, sendingShownQRCode.SharedSecret)
			assert.Equal(t, txnID, sendingShownQRCode.TransactionID)

			// See the spec for the QR Code format:
			// https://spec.matrix.org/v1.10/client-server-api/#qr-code-format
			if tc.receivingGeneratedCrossSigningKeys {
				masterKeyBytes := receivingMachine.GetOwnCrossSigningPublicKeys(ctx).MasterKey.Bytes()

				// The receiving device should have shown a QR Code with
				// trusted mode
				assert.Equal(t, verificationhelper.QRCodeModeSelfVerifyingMasterKeyTrusted, receivingShownQRCode.Mode)
				assert.EqualValues(t, masterKeyBytes, receivingShownQRCode.Key1)                                  // master key
				assert.EqualValues(t, sendingMachine.OwnIdentity().SigningKey.Bytes(), receivingShownQRCode.Key2) // other device key

				// The sending device should have shown a QR code with
				// untrusted mode.
				assert.Equal(t, verificationhelper.QRCodeModeSelfVerifyingMasterKeyUntrusted, sendingShownQRCode.Mode)
				assert.EqualValues(t, sendingMachine.OwnIdentity().SigningKey.Bytes(), sendingShownQRCode.Key1) // own device key
				assert.EqualValues(t, masterKeyBytes, sendingShownQRCode.Key2)                                  // master key
			} else if tc.sendingGeneratedCrossSigningKeys {
				masterKeyBytes := sendingMachine.GetOwnCrossSigningPublicKeys(ctx).MasterKey.Bytes()

				// The receiving device should have shown a QR code with
				// untrusted mode
				assert.Equal(t, verificationhelper.QRCodeModeSelfVerifyingMasterKeyUntrusted, receivingShownQRCode.Mode)
				assert.EqualValues(t, receivingMachine.OwnIdentity().SigningKey.Bytes(), receivingShownQRCode.Key1) // own device key
				assert.EqualValues(t, masterKeyBytes, receivingShownQRCode.Key2)                                    // master key

				// The sending device should have shown a QR code with trusted
				// mode.
				assert.Equal(t, verificationhelper.QRCodeModeSelfVerifyingMasterKeyTrusted, sendingShownQRCode.Mode)
				assert.EqualValues(t, masterKeyBytes, sendingShownQRCode.Key1)                                    // master key
				assert.EqualValues(t, receivingMachine.OwnIdentity().SigningKey.Bytes(), sendingShownQRCode.Key2) // other device key
			}
		})
	}
}

// TestAcceptSelfVerificationCancelOnNonParticipatingDevices ensures that we do
// not regress https://github.com/mautrix/go/pull/230.
func TestSelfVerification_Accept_CancelOnNonParticipatingDevices(t *testing.T) {
	ctx := log.Logger.WithContext(context.TODO())
	ts, sendingClient, receivingClient, sendingCryptoStore, receivingCryptoStore, sendingMachine, receivingMachine := initServerAndLogin(t, ctx)
	defer ts.Close()
	_, _, sendingHelper, receivingHelper := initDefaultCallbacks(t, ctx, sendingClient, receivingClient, sendingMachine, receivingMachine)

	nonParticipatingDeviceID1 := id.DeviceID("non-participating1")
	nonParticipatingDeviceID2 := id.DeviceID("non-participating2")
	addDeviceID(ctx, sendingCryptoStore, userID, nonParticipatingDeviceID1)
	addDeviceID(ctx, sendingCryptoStore, userID, nonParticipatingDeviceID2)
	addDeviceID(ctx, receivingCryptoStore, userID, nonParticipatingDeviceID1)
	addDeviceID(ctx, receivingCryptoStore, userID, nonParticipatingDeviceID2)

	_, _, err := sendingMachine.GenerateAndUploadCrossSigningKeys(ctx, nil, "")
	assert.NoError(t, err)

	// Send the verification request from the sender device and accept it on
	// the receiving device.
	txnID, err := sendingHelper.StartVerification(ctx, userID)
	require.NoError(t, err)
	ts.dispatchToDevice(t, ctx, receivingClient)
	err = receivingHelper.AcceptVerification(ctx, txnID)
	require.NoError(t, err)

	// Receive the m.key.verification.ready event on the sending device.
	ts.dispatchToDevice(t, ctx, sendingClient)

	// The sending and receiving devices should not have any cancellation
	// events in their inboxes.
	assert.Empty(t, ts.DeviceInbox[userID][sendingDeviceID])
	assert.Empty(t, ts.DeviceInbox[userID][receivingDeviceID])

	// There should now be cancellation events in the non-participating devices
	// inboxes (in addition to the request event).
	assert.Len(t, ts.DeviceInbox[userID][nonParticipatingDeviceID1], 2)
	assert.Len(t, ts.DeviceInbox[userID][nonParticipatingDeviceID2], 2)
	assert.Equal(t, ts.DeviceInbox[userID][nonParticipatingDeviceID1][1], ts.DeviceInbox[userID][nonParticipatingDeviceID2][1])
	cancellationEvent := ts.DeviceInbox[userID][nonParticipatingDeviceID1][1].Content.AsVerificationCancel()
	assert.Equal(t, txnID, cancellationEvent.TransactionID)
	assert.Equal(t, event.VerificationCancelCodeAccepted, cancellationEvent.Code)
}

func TestSelfVerification_ScanQRAndConfirmScan(t *testing.T) {
	ctx := log.Logger.WithContext(context.TODO())

	testCases := []struct {
		sendingGeneratedCrossSigningKeys bool
		sendingScansQR                   bool // false indicates that receiving device should emulate a scan
	}{
		{false, false},
		{false, true},
		{true, false},
		{true, true},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("sendingGeneratedCrossSigningKeys=%t sendingScansQR=%t", tc.sendingGeneratedCrossSigningKeys, tc.sendingScansQR), func(t *testing.T) {
			ts, sendingClient, receivingClient, _, _, sendingMachine, receivingMachine := initServerAndLogin(t, ctx)
			defer ts.Close()
			sendingCallbacks, receivingCallbacks, sendingHelper, receivingHelper := initDefaultCallbacks(t, ctx, sendingClient, receivingClient, sendingMachine, receivingMachine)
			var err error

			if tc.sendingGeneratedCrossSigningKeys {
				_, _, err = sendingMachine.GenerateAndUploadCrossSigningKeys(ctx, nil, "")
				require.NoError(t, err)
			} else {
				_, _, err = receivingMachine.GenerateAndUploadCrossSigningKeys(ctx, nil, "")
				require.NoError(t, err)
			}

			// Send the verification request from the sender device and accept
			// it on the receiving device and receive the verification ready
			// event on the sending device.
			txnID, err := sendingHelper.StartVerification(ctx, userID)
			require.NoError(t, err)
			ts.dispatchToDevice(t, ctx, receivingClient)
			err = receivingHelper.AcceptVerification(ctx, txnID)
			require.NoError(t, err)
			ts.dispatchToDevice(t, ctx, sendingClient)

			receivingShownQRCode := receivingCallbacks.GetQRCodeShown(txnID)
			require.NotNil(t, receivingShownQRCode)
			sendingShownQRCode := sendingCallbacks.GetQRCodeShown(txnID)
			require.NotNil(t, sendingShownQRCode)

			if tc.sendingScansQR {
				// Emulate scanning the QR code shown by the receiving device
				// on the sending device.
				err := sendingHelper.HandleScannedQRData(ctx, receivingShownQRCode.Bytes())
				require.NoError(t, err)

				// Ensure that the receiving device received a verification
				// start event and a verification done event.
				receivingInbox := ts.DeviceInbox[userID][receivingDeviceID]
				assert.Len(t, receivingInbox, 2)

				startEvt := receivingInbox[0].Content.AsVerificationStart()
				assert.Equal(t, txnID, startEvt.TransactionID)
				assert.Equal(t, sendingDeviceID, startEvt.FromDevice)
				assert.Equal(t, event.VerificationMethodReciprocate, startEvt.Method)
				assert.EqualValues(t, receivingShownQRCode.SharedSecret, startEvt.Secret)

				doneEvt := receivingInbox[1].Content.AsVerificationDone()
				assert.Equal(t, txnID, doneEvt.TransactionID)

				// Handle the start and done events on the receiving client and
				// confirm the scan.
				ts.dispatchToDevice(t, ctx, receivingClient)

				// Ensure that the receiving device detected that its QR code
				// was scanned.
				assert.True(t, receivingCallbacks.WasOurQRCodeScanned(txnID))
				err = receivingHelper.ConfirmQRCodeScanned(ctx, txnID)
				require.NoError(t, err)

				// Ensure that the sending device received a verification done
				// event.
				sendingInbox := ts.DeviceInbox[userID][sendingDeviceID]
				require.Len(t, sendingInbox, 1)
				doneEvt = sendingInbox[0].Content.AsVerificationDone()
				assert.Equal(t, txnID, doneEvt.TransactionID)

				ts.dispatchToDevice(t, ctx, sendingClient)
			} else { // receiving scans QR
				// Emulate scanning the QR code shown by the sending device on
				// the receiving device.
				err := receivingHelper.HandleScannedQRData(ctx, sendingShownQRCode.Bytes())
				require.NoError(t, err)

				// Ensure that the sending device received a verification
				// start event and a verification done event.
				sendingInbox := ts.DeviceInbox[userID][sendingDeviceID]
				assert.Len(t, sendingInbox, 2)

				startEvt := sendingInbox[0].Content.AsVerificationStart()
				assert.Equal(t, txnID, startEvt.TransactionID)
				assert.Equal(t, receivingDeviceID, startEvt.FromDevice)
				assert.Equal(t, event.VerificationMethodReciprocate, startEvt.Method)
				assert.EqualValues(t, sendingShownQRCode.SharedSecret, startEvt.Secret)

				doneEvt := sendingInbox[1].Content.AsVerificationDone()
				assert.Equal(t, txnID, doneEvt.TransactionID)

				// Handle the start and done events on the receiving client and
				// confirm the scan.
				ts.dispatchToDevice(t, ctx, sendingClient)

				// Ensure that the sending device detected that its QR code was
				// scanned.
				assert.True(t, sendingCallbacks.WasOurQRCodeScanned(txnID))
				err = sendingHelper.ConfirmQRCodeScanned(ctx, txnID)
				require.NoError(t, err)

				// Ensure that the receiving device received a verification
				// done event.
				receivingInbox := ts.DeviceInbox[userID][receivingDeviceID]
				require.Len(t, receivingInbox, 1)
				doneEvt = receivingInbox[0].Content.AsVerificationDone()
				assert.Equal(t, txnID, doneEvt.TransactionID)

				ts.dispatchToDevice(t, ctx, receivingClient)
			}

			// Ensure that both devices have marked the verification as done.
			assert.True(t, sendingCallbacks.IsVerificationDone(txnID))
			assert.True(t, receivingCallbacks.IsVerificationDone(txnID))
		})
	}
}

func TestSelfVerification_ErrorOnDoubleAccept(t *testing.T) {
	ctx := log.Logger.WithContext(context.TODO())
	ts, sendingClient, receivingClient, _, _, sendingMachine, receivingMachine := initServerAndLogin(t, ctx)
	defer ts.Close()
	_, _, sendingHelper, receivingHelper := initDefaultCallbacks(t, ctx, sendingClient, receivingClient, sendingMachine, receivingMachine)

	_, _, err := sendingMachine.GenerateAndUploadCrossSigningKeys(ctx, nil, "")
	require.NoError(t, err)

	txnID, err := sendingHelper.StartVerification(ctx, userID)
	require.NoError(t, err)
	ts.dispatchToDevice(t, ctx, receivingClient)
	err = receivingHelper.AcceptVerification(ctx, txnID)
	require.NoError(t, err)
	err = receivingHelper.AcceptVerification(ctx, txnID)
	require.ErrorContains(t, err, "transaction is not in the requested state")
}

func TestSelfVerification_ScanQRTransactionIDCorrupted(t *testing.T) {
	ctx := log.Logger.WithContext(context.TODO())

	ts, sendingClient, receivingClient, _, _, sendingMachine, receivingMachine := initServerAndLogin(t, ctx)
	defer ts.Close()
	sendingCallbacks, receivingCallbacks, sendingHelper, receivingHelper := initDefaultCallbacks(t, ctx, sendingClient, receivingClient, sendingMachine, receivingMachine)
	var err error

	_, _, err = sendingMachine.GenerateAndUploadCrossSigningKeys(ctx, nil, "")
	require.NoError(t, err)

	// Send the verification request from the sender device and accept
	// it on the receiving device and receive the verification ready
	// event on the sending device.
	txnID, err := sendingHelper.StartVerification(ctx, userID)
	require.NoError(t, err)
	ts.dispatchToDevice(t, ctx, receivingClient)
	err = receivingHelper.AcceptVerification(ctx, txnID)
	require.NoError(t, err)
	ts.dispatchToDevice(t, ctx, sendingClient)

	receivingShownQRCodeBytes := receivingCallbacks.GetQRCodeShown(txnID).Bytes()
	sendingShownQRCodeBytes := sendingCallbacks.GetQRCodeShown(txnID).Bytes()

	// Corrupt the QR codes (the 20th byte should be in the transaction ID)
	receivingShownQRCodeBytes[20]++
	sendingShownQRCodeBytes[20]++

	// Emulate scanning the QR code shown by the receiving device
	// on the sending device.
	err = sendingHelper.HandleScannedQRData(ctx, receivingShownQRCodeBytes)
	assert.ErrorContains(t, err, "unknown transaction ID found in QR code")

	// Emulate scanning the QR code shown by the sending device on
	// the receiving device.
	err = receivingHelper.HandleScannedQRData(ctx, sendingShownQRCodeBytes)
	assert.ErrorContains(t, err, "unknown transaction ID found in QR code")
}

func TestSelfVerification_ScanQRKeyCorrupted(t *testing.T) {
	ctx := log.Logger.WithContext(context.TODO())

	testCases := []struct {
		sendingGeneratedCrossSigningKeys bool
		sendingScansQR                   bool // false indicates that receiving device should emulate a scan
		corruptByte                      int
		expectedError                    string
	}{
		// The 50th byte should be in the first key
		{false, false, 50, "the other device's key is not what we expected"}, // receiver scans sender QR code, sender doesn't trust the master key => mode 0x02 => key1 == sender device key
		{false, true, 50, "the master key does not match"},                   // sender scans receiver QR code, receiver trusts the master key => mode 0x01 => key1 == master key
		{true, false, 50, "the master key does not match"},                   // receiver scans sender QR code, sender trusts the master key => mode 0x01 => key1 == master key
		{true, true, 50, "the other device's key is not what we expected"},   // sender scans receiver QR Code, receiver doesn't trust the master key => mode 0x02 => key1 == receiver device key
		// The 100th byte should be in the second key
		{false, false, 100, "the master key does not match"},                     // receiver scans sender QR code, sender doesn't trust the master key => mode 0x02 => key2 == master key
		{false, true, 100, "the other device has the wrong key for this device"}, // sender scans receiver QR code, receiver trusts the master key => mode 0x01 => key2 == sender device key
		{true, false, 100, "the other device has the wrong key for this device"}, // receiver scans sender QR code, sender trusts the master key => mode 0x01 => key2 == receiver device key
		{true, true, 100, "the master key does not match"},                       // sender scans receiver QR Code, receiver doesn't trust the master key => mode 0x02 => key2 == master key
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("sendingGeneratedCrossSigningKeys=%t sendingScansQR=%t corrupt=%d", tc.sendingGeneratedCrossSigningKeys, tc.sendingScansQR, tc.corruptByte), func(t *testing.T) {
			ts, sendingClient, receivingClient, _, _, sendingMachine, receivingMachine := initServerAndLogin(t, ctx)
			defer ts.Close()
			sendingCallbacks, receivingCallbacks, sendingHelper, receivingHelper := initDefaultCallbacks(t, ctx, sendingClient, receivingClient, sendingMachine, receivingMachine)
			var err error

			if tc.sendingGeneratedCrossSigningKeys {
				_, _, err = sendingMachine.GenerateAndUploadCrossSigningKeys(ctx, nil, "")
				require.NoError(t, err)
			} else {
				_, _, err = receivingMachine.GenerateAndUploadCrossSigningKeys(ctx, nil, "")
				require.NoError(t, err)
			}

			// Send the verification request from the sender device and accept
			// it on the receiving device and receive the verification ready
			// event on the sending device.
			txnID, err := sendingHelper.StartVerification(ctx, userID)
			require.NoError(t, err)
			ts.dispatchToDevice(t, ctx, receivingClient)
			err = receivingHelper.AcceptVerification(ctx, txnID)
			require.NoError(t, err)
			ts.dispatchToDevice(t, ctx, sendingClient)

			receivingShownQRCodeBytes := receivingCallbacks.GetQRCodeShown(txnID).Bytes()
			sendingShownQRCodeBytes := sendingCallbacks.GetQRCodeShown(txnID).Bytes()

			// Corrupt the QR codes
			receivingShownQRCodeBytes[tc.corruptByte]++
			sendingShownQRCodeBytes[tc.corruptByte]++

			if tc.sendingScansQR {
				// Emulate scanning the QR code shown by the receiving device
				// on the sending device.
				err := sendingHelper.HandleScannedQRData(ctx, receivingShownQRCodeBytes)
				assert.ErrorContains(t, err, tc.expectedError)

				// Ensure that the receiving device received a cancellation.
				receivingInbox := ts.DeviceInbox[userID][receivingDeviceID]
				assert.Len(t, receivingInbox, 1)
				ts.dispatchToDevice(t, ctx, receivingClient)
				cancellation := receivingCallbacks.GetVerificationCancellation(txnID)
				require.NotNil(t, cancellation)
				assert.Equal(t, event.VerificationCancelCodeKeyMismatch, cancellation.Code)
				assert.Equal(t, tc.expectedError, cancellation.Reason)
			} else { // receiving scans QR
				// Emulate scanning the QR code shown by the sending device on
				// the receiving device.
				err := receivingHelper.HandleScannedQRData(ctx, sendingShownQRCodeBytes)
				assert.ErrorContains(t, err, tc.expectedError)

				// Ensure that the sending device received a cancellation.
				sendingInbox := ts.DeviceInbox[userID][sendingDeviceID]
				assert.Len(t, sendingInbox, 1)
				ts.dispatchToDevice(t, ctx, sendingClient)
				cancellation := sendingCallbacks.GetVerificationCancellation(txnID)
				require.NotNil(t, cancellation)
				assert.Equal(t, event.VerificationCancelCodeKeyMismatch, cancellation.Code)
				assert.Equal(t, tc.expectedError, cancellation.Reason)
			}
		})
	}
}
