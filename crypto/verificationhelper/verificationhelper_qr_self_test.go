// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package verificationhelper_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/rs/zerolog/log" // zerolog-allow-global-log
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/event"
)

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
			ts, sendingClient, receivingClient, _, _, sendingMachine, receivingMachine := initServerAndLoginTwoAlice(t, ctx)
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
			txnID, err := sendingHelper.StartVerification(ctx, aliceUserID)
			require.NoError(t, err)
			ts.DispatchToDevice(t, ctx, receivingClient)

			err = receivingHelper.AcceptVerification(ctx, txnID)
			if tc.expectedAcceptError != "" {
				assert.ErrorContains(t, err, tc.expectedAcceptError)
				return
			} else {
				require.NoError(t, err)
			}

			ts.DispatchToDevice(t, ctx, sendingClient)

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
			ts, sendingClient, receivingClient, _, _, sendingMachine, receivingMachine := initServerAndLoginTwoAlice(t, ctx)
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
			txnID, err := sendingHelper.StartVerification(ctx, aliceUserID)
			require.NoError(t, err)
			ts.DispatchToDevice(t, ctx, receivingClient)
			err = receivingHelper.AcceptVerification(ctx, txnID)
			require.NoError(t, err)
			ts.DispatchToDevice(t, ctx, sendingClient)

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
				receivingInbox := ts.DeviceInbox[aliceUserID][receivingDeviceID]
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
				ts.DispatchToDevice(t, ctx, receivingClient)

				// Ensure that the receiving device detected that its QR code
				// was scanned.
				assert.True(t, receivingCallbacks.WasOurQRCodeScanned(txnID))
				err = receivingHelper.ConfirmQRCodeScanned(ctx, txnID)
				require.NoError(t, err)

				// Ensure that the sending device received a verification done
				// event.
				sendingInbox := ts.DeviceInbox[aliceUserID][sendingDeviceID]
				require.Len(t, sendingInbox, 1)
				doneEvt = sendingInbox[0].Content.AsVerificationDone()
				assert.Equal(t, txnID, doneEvt.TransactionID)

				ts.DispatchToDevice(t, ctx, sendingClient)
			} else { // receiving scans QR
				// Emulate scanning the QR code shown by the sending device on
				// the receiving device.
				err := receivingHelper.HandleScannedQRData(ctx, sendingShownQRCode.Bytes())
				require.NoError(t, err)

				// Ensure that the sending device received a verification
				// start event and a verification done event.
				sendingInbox := ts.DeviceInbox[aliceUserID][sendingDeviceID]
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
				ts.DispatchToDevice(t, ctx, sendingClient)

				// Ensure that the sending device detected that its QR code was
				// scanned.
				assert.True(t, sendingCallbacks.WasOurQRCodeScanned(txnID))
				err = sendingHelper.ConfirmQRCodeScanned(ctx, txnID)
				require.NoError(t, err)

				// Ensure that the receiving device received a verification
				// done event.
				receivingInbox := ts.DeviceInbox[aliceUserID][receivingDeviceID]
				require.Len(t, receivingInbox, 1)
				doneEvt = receivingInbox[0].Content.AsVerificationDone()
				assert.Equal(t, txnID, doneEvt.TransactionID)

				ts.DispatchToDevice(t, ctx, receivingClient)
			}

			// Ensure that both devices have marked the verification as done.
			assert.True(t, sendingCallbacks.IsVerificationDone(txnID))
			assert.True(t, receivingCallbacks.IsVerificationDone(txnID))
		})
	}
}

func TestSelfVerification_ScanQRTransactionIDCorrupted(t *testing.T) {
	ctx := log.Logger.WithContext(context.TODO())

	ts, sendingClient, receivingClient, _, _, sendingMachine, receivingMachine := initServerAndLoginTwoAlice(t, ctx)
	sendingCallbacks, receivingCallbacks, sendingHelper, receivingHelper := initDefaultCallbacks(t, ctx, sendingClient, receivingClient, sendingMachine, receivingMachine)
	var err error

	_, _, err = sendingMachine.GenerateAndUploadCrossSigningKeys(ctx, nil, "")
	require.NoError(t, err)

	// Send the verification request from the sender device and accept
	// it on the receiving device and receive the verification ready
	// event on the sending device.
	txnID, err := sendingHelper.StartVerification(ctx, aliceUserID)
	require.NoError(t, err)
	ts.DispatchToDevice(t, ctx, receivingClient)
	err = receivingHelper.AcceptVerification(ctx, txnID)
	require.NoError(t, err)
	ts.DispatchToDevice(t, ctx, sendingClient)

	receivingShownQRCodeBytes := receivingCallbacks.GetQRCodeShown(txnID).Bytes()
	sendingShownQRCodeBytes := sendingCallbacks.GetQRCodeShown(txnID).Bytes()

	// Corrupt the QR codes (the 20th byte should be in the transaction ID)
	receivingShownQRCodeBytes[20]++
	sendingShownQRCodeBytes[20]++

	// Emulate scanning the QR code shown by the receiving device
	// on the sending device.
	err = sendingHelper.HandleScannedQRData(ctx, receivingShownQRCodeBytes)
	assert.ErrorContains(t, err, "unknown transaction ID")

	// Emulate scanning the QR code shown by the sending device on
	// the receiving device.
	err = receivingHelper.HandleScannedQRData(ctx, sendingShownQRCodeBytes)
	assert.ErrorContains(t, err, "unknown transaction ID")
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
			ts, sendingClient, receivingClient, _, _, sendingMachine, receivingMachine := initServerAndLoginTwoAlice(t, ctx)
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
			txnID, err := sendingHelper.StartVerification(ctx, aliceUserID)
			require.NoError(t, err)
			ts.DispatchToDevice(t, ctx, receivingClient)
			err = receivingHelper.AcceptVerification(ctx, txnID)
			require.NoError(t, err)
			ts.DispatchToDevice(t, ctx, sendingClient)

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
				receivingInbox := ts.DeviceInbox[aliceUserID][receivingDeviceID]
				assert.Len(t, receivingInbox, 1)
				ts.DispatchToDevice(t, ctx, receivingClient)
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
				sendingInbox := ts.DeviceInbox[aliceUserID][sendingDeviceID]
				assert.Len(t, sendingInbox, 1)
				ts.DispatchToDevice(t, ctx, sendingClient)
				cancellation := sendingCallbacks.GetVerificationCancellation(txnID)
				require.NotNil(t, cancellation)
				assert.Equal(t, event.VerificationCancelCodeKeyMismatch, cancellation.Code)
				assert.Equal(t, tc.expectedError, cancellation.Reason)
			}
		})
	}
}
