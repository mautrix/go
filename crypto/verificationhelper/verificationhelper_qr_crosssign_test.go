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

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func TestCrossSignVerification_ScanQRAndConfirmScan(t *testing.T) {
	ctx := log.Logger.WithContext(context.TODO())

	testCases := []struct {
		sendingScansQR bool // false indicates that receiving device should emulate a scan
	}{
		{false},
		{true},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("sendingScansQR=%t", tc.sendingScansQR), func(t *testing.T) {
			ts, sendingClient, receivingClient, _, _, sendingMachine, receivingMachine := initServerAndLoginAliceBob(t, ctx)
			sendingCallbacks, receivingCallbacks, sendingHelper, receivingHelper := initDefaultCallbacks(t, ctx, sendingClient, receivingClient, sendingMachine, receivingMachine)
			var err error

			// Generate cross-signing keys for both users
			_, _, err = sendingMachine.GenerateAndUploadCrossSigningKeys(ctx, nil, "")
			require.NoError(t, err)
			_, _, err = receivingMachine.GenerateAndUploadCrossSigningKeys(ctx, nil, "")
			require.NoError(t, err)

			// Fetch each other's keys
			sendingMachine.FetchKeys(ctx, []id.UserID{bobUserID}, true)
			receivingMachine.FetchKeys(ctx, []id.UserID{aliceUserID}, true)

			// Send the verification request from the sender device and accept
			// it on the receiving device and receive the verification ready
			// event on the sending device.
			txnID, err := sendingHelper.StartVerification(ctx, bobUserID)
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
				receivingInbox := ts.DeviceInbox[bobUserID][receivingDeviceID]
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
				receivingInbox := ts.DeviceInbox[bobUserID][receivingDeviceID]
				require.Len(t, receivingInbox, 1)
				doneEvt = receivingInbox[0].Content.AsVerificationDone()
				assert.Equal(t, txnID, doneEvt.TransactionID)

				ts.DispatchToDevice(t, ctx, receivingClient)
			}

			// Ensure that both devices have marked the verification as done.
			assert.True(t, sendingCallbacks.IsVerificationDone(txnID))
			assert.True(t, receivingCallbacks.IsVerificationDone(txnID))

			bobTrustsAlice, err := receivingMachine.IsUserTrusted(ctx, aliceUserID)
			assert.NoError(t, err)
			assert.True(t, bobTrustsAlice)
			aliceTrustsBob, err := sendingMachine.IsUserTrusted(ctx, bobUserID)
			assert.NoError(t, err)
			assert.True(t, aliceTrustsBob)
		})
	}
}
