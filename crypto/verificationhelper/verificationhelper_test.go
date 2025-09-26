package verificationhelper_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log" // zerolog-allow-global-log
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/cryptohelper"
	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/mockserver"
)

var aliceUserID = id.UserID("@alice:example.org")
var bobUserID = id.UserID("@bob:example.org")
var sendingDeviceID = id.DeviceID("sending")
var receivingDeviceID = id.DeviceID("receiving")

func init() {
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).With().Timestamp().Logger().Level(zerolog.TraceLevel)
	zerolog.DefaultContextLogger = &log.Logger
}

func addDeviceID(ctx context.Context, cryptoStore crypto.Store, userID id.UserID, deviceID id.DeviceID) {
	err := cryptoStore.PutDevice(ctx, userID, &id.Device{
		UserID:   userID,
		DeviceID: deviceID,
	})
	if err != nil {
		panic(err)
	}
}

func initServerAndLoginTwoAlice(t *testing.T, ctx context.Context) (ts *mockserver.MockServer, sendingClient, receivingClient *mautrix.Client, sendingCryptoStore, receivingCryptoStore crypto.Store, sendingMachine, receivingMachine *crypto.OlmMachine) {
	t.Helper()
	ts = mockserver.Create(t)

	sendingClient, sendingCryptoStore = ts.Login(t, ctx, aliceUserID, sendingDeviceID)
	sendingMachine = sendingClient.Crypto.(*cryptohelper.CryptoHelper).Machine()
	receivingClient, receivingCryptoStore = ts.Login(t, ctx, aliceUserID, receivingDeviceID)
	receivingMachine = receivingClient.Crypto.(*cryptohelper.CryptoHelper).Machine()

	require.NoError(t, sendingCryptoStore.PutDevice(ctx, aliceUserID, sendingMachine.OwnIdentity()))
	require.NoError(t, sendingCryptoStore.PutDevice(ctx, aliceUserID, receivingMachine.OwnIdentity()))
	require.NoError(t, receivingCryptoStore.PutDevice(ctx, aliceUserID, sendingMachine.OwnIdentity()))
	require.NoError(t, receivingCryptoStore.PutDevice(ctx, aliceUserID, receivingMachine.OwnIdentity()))
	return
}

func initServerAndLoginAliceBob(t *testing.T, ctx context.Context) (ts *mockserver.MockServer, sendingClient, receivingClient *mautrix.Client, sendingCryptoStore, receivingCryptoStore crypto.Store, sendingMachine, receivingMachine *crypto.OlmMachine) {
	t.Helper()
	ts = mockserver.Create(t)

	sendingClient, sendingCryptoStore = ts.Login(t, ctx, aliceUserID, sendingDeviceID)
	sendingMachine = sendingClient.Crypto.(*cryptohelper.CryptoHelper).Machine()
	receivingClient, receivingCryptoStore = ts.Login(t, ctx, bobUserID, receivingDeviceID)
	receivingMachine = receivingClient.Crypto.(*cryptohelper.CryptoHelper).Machine()

	require.NoError(t, sendingCryptoStore.PutDevice(ctx, aliceUserID, sendingMachine.OwnIdentity()))
	require.NoError(t, sendingCryptoStore.PutDevice(ctx, bobUserID, receivingMachine.OwnIdentity()))
	require.NoError(t, receivingCryptoStore.PutDevice(ctx, aliceUserID, sendingMachine.OwnIdentity()))
	require.NoError(t, receivingCryptoStore.PutDevice(ctx, bobUserID, receivingMachine.OwnIdentity()))
	return
}

func initDefaultCallbacks(t *testing.T, ctx context.Context, sendingClient, receivingClient *mautrix.Client, sendingMachine, receivingMachine *crypto.OlmMachine) (sendingCallbacks, receivingCallbacks *allVerificationCallbacks, sendingHelper, receivingHelper *verificationhelper.VerificationHelper) {
	t.Helper()
	sendingCallbacks = newAllVerificationCallbacks()
	senderVerificationDB, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	senderVerificationStore, err := NewSQLiteVerificationStore(ctx, senderVerificationDB)
	require.NoError(t, err)

	sendingHelper = verificationhelper.NewVerificationHelper(sendingClient, sendingMachine, senderVerificationStore, sendingCallbacks, true, true, true)
	require.NoError(t, sendingHelper.Init(ctx))

	receivingCallbacks = newAllVerificationCallbacks()
	receiverVerificationDB, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	receiverVerificationStore, err := NewSQLiteVerificationStore(ctx, receiverVerificationDB)
	require.NoError(t, err)
	receivingHelper = verificationhelper.NewVerificationHelper(receivingClient, receivingMachine, receiverVerificationStore, receivingCallbacks, true, true, true)
	require.NoError(t, receivingHelper.Init(ctx))
	return
}

func TestVerification_Start(t *testing.T) {
	ctx := log.Logger.WithContext(context.TODO())
	receivingDeviceID2 := id.DeviceID("receiving2")

	testCases := []struct {
		supportsShow                bool
		supportsScan                bool
		supportsSAS                 bool
		callbacks                   MockVerificationCallbacks
		startVerificationErrMsg     string
		expectedVerificationMethods []event.VerificationMethod
	}{
		{false, false, false, newBaseVerificationCallbacks(), "no supported verification methods", nil},
		{false, true, false, newBaseVerificationCallbacks(), "", []event.VerificationMethod{event.VerificationMethodQRCodeScan, event.VerificationMethodReciprocate}},

		{false, false, false, newShowQRCodeVerificationCallbacks(), "no supported verification methods", nil},
		{true, false, false, newShowQRCodeVerificationCallbacks(), "", []event.VerificationMethod{event.VerificationMethodQRCodeShow, event.VerificationMethodReciprocate}},
		{false, true, false, newShowQRCodeVerificationCallbacks(), "", []event.VerificationMethod{event.VerificationMethodQRCodeScan, event.VerificationMethodReciprocate}},
		{true, true, false, newShowQRCodeVerificationCallbacks(), "", []event.VerificationMethod{event.VerificationMethodQRCodeShow, event.VerificationMethodQRCodeScan, event.VerificationMethodReciprocate}},

		{false, false, true, newSASVerificationCallbacks(), "", []event.VerificationMethod{event.VerificationMethodSAS}},
		{false, true, true, newSASVerificationCallbacks(), "", []event.VerificationMethod{event.VerificationMethodSAS, event.VerificationMethodQRCodeScan, event.VerificationMethodReciprocate}},

		{false, false, false, newAllVerificationCallbacks(), "no supported verification methods", nil},
		{false, false, true, newAllVerificationCallbacks(), "", []event.VerificationMethod{event.VerificationMethodSAS}},
		{false, true, true, newAllVerificationCallbacks(), "", []event.VerificationMethod{event.VerificationMethodSAS, event.VerificationMethodQRCodeScan, event.VerificationMethodReciprocate}},
		{true, false, true, newAllVerificationCallbacks(), "", []event.VerificationMethod{event.VerificationMethodSAS, event.VerificationMethodQRCodeShow, event.VerificationMethodReciprocate}},
		{true, true, true, newAllVerificationCallbacks(), "", []event.VerificationMethod{event.VerificationMethodSAS, event.VerificationMethodQRCodeShow, event.VerificationMethodQRCodeScan, event.VerificationMethodReciprocate}},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			ts := mockserver.Create(t)

			client, cryptoStore := ts.Login(t, ctx, aliceUserID, sendingDeviceID)
			addDeviceID(ctx, cryptoStore, aliceUserID, sendingDeviceID)
			addDeviceID(ctx, cryptoStore, aliceUserID, receivingDeviceID)
			addDeviceID(ctx, cryptoStore, aliceUserID, receivingDeviceID2)

			senderHelper := verificationhelper.NewVerificationHelper(client, client.Crypto.(*cryptohelper.CryptoHelper).Machine(), nil, tc.callbacks, tc.supportsShow, tc.supportsScan, tc.supportsSAS)
			err := senderHelper.Init(ctx)
			require.NoError(t, err)

			txnID, err := senderHelper.StartVerification(ctx, aliceUserID)
			if tc.startVerificationErrMsg != "" {
				assert.ErrorContains(t, err, tc.startVerificationErrMsg)
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, txnID)

			toDeviceInbox := ts.DeviceInbox[aliceUserID]

			// Ensure that we didn't send a verification request to the
			// sending device.
			assert.Empty(t, toDeviceInbox[sendingDeviceID])

			// Ensure that the verification request was sent to both of
			// the other devices.
			assert.NotEmpty(t, toDeviceInbox[receivingDeviceID])
			assert.NotEmpty(t, toDeviceInbox[receivingDeviceID2])
			assert.Equal(t, toDeviceInbox[receivingDeviceID], toDeviceInbox[receivingDeviceID2])
			require.Len(t, toDeviceInbox[receivingDeviceID], 1)

			// Ensure that the verification request is correct.
			verificationRequest := toDeviceInbox[receivingDeviceID][0].Content.AsVerificationRequest()
			assert.Equal(t, sendingDeviceID, verificationRequest.FromDevice)
			assert.Equal(t, txnID, verificationRequest.TransactionID)
			assert.ElementsMatch(t, tc.expectedVerificationMethods, verificationRequest.Methods)
		})
	}
}

func TestVerification_StartThenCancel(t *testing.T) {
	ctx := log.Logger.WithContext(context.TODO())
	bystanderDeviceID := id.DeviceID("bystander")

	for _, sendingCancels := range []bool{true, false} {
		t.Run(fmt.Sprintf("sendingCancels=%t", sendingCancels), func(t *testing.T) {
			ts, sendingClient, receivingClient, sendingCryptoStore, receivingCryptoStore, sendingMachine, receivingMachine := initServerAndLoginTwoAlice(t, ctx)
			_, _, sendingHelper, receivingHelper := initDefaultCallbacks(t, ctx, sendingClient, receivingClient, sendingMachine, receivingMachine)

			bystanderClient, _ := ts.Login(t, ctx, aliceUserID, bystanderDeviceID)
			bystanderMachine := bystanderClient.Crypto.(*cryptohelper.CryptoHelper).Machine()
			bystanderHelper := verificationhelper.NewVerificationHelper(bystanderClient, bystanderMachine, nil, newAllVerificationCallbacks(), true, true, true)
			require.NoError(t, bystanderHelper.Init(ctx))

			require.NoError(t, sendingCryptoStore.PutDevice(ctx, aliceUserID, bystanderMachine.OwnIdentity()))
			require.NoError(t, receivingCryptoStore.PutDevice(ctx, aliceUserID, bystanderMachine.OwnIdentity()))

			txnID, err := sendingHelper.StartVerification(ctx, aliceUserID)
			require.NoError(t, err)

			assert.Empty(t, ts.DeviceInbox[aliceUserID][sendingDeviceID])

			// Process the request event on the receiving device.
			receivingInbox := ts.DeviceInbox[aliceUserID][receivingDeviceID]
			assert.Len(t, receivingInbox, 1)
			assert.Equal(t, txnID, receivingInbox[0].Content.AsVerificationRequest().TransactionID)
			ts.DispatchToDevice(t, ctx, receivingClient)

			// Process the request event on the bystander device.
			bystanderInbox := ts.DeviceInbox[aliceUserID][bystanderDeviceID]
			assert.Len(t, bystanderInbox, 1)
			assert.Equal(t, txnID, bystanderInbox[0].Content.AsVerificationRequest().TransactionID)
			ts.DispatchToDevice(t, ctx, bystanderClient)

			// Cancel the verification request.
			var cancelEvt *event.VerificationCancelEventContent
			if sendingCancels {
				err = sendingHelper.CancelVerification(ctx, txnID, event.VerificationCancelCodeUser, "Recovery code preferred")
				assert.NoError(t, err)

				// The sending device should not have a cancellation event.
				assert.Empty(t, ts.DeviceInbox[aliceUserID][sendingDeviceID])

				// Ensure that the cancellation event was sent to the receiving device.
				assert.Len(t, ts.DeviceInbox[aliceUserID][receivingDeviceID], 1)
				cancelEvt = ts.DeviceInbox[aliceUserID][receivingDeviceID][0].Content.AsVerificationCancel()

				// Ensure that the cancellation event was sent to the bystander device.
				assert.Len(t, ts.DeviceInbox[aliceUserID][bystanderDeviceID], 1)
				bystanderCancelEvt := ts.DeviceInbox[aliceUserID][bystanderDeviceID][0].Content.AsVerificationCancel()
				assert.Equal(t, cancelEvt, bystanderCancelEvt)
			} else {
				err = receivingHelper.CancelVerification(ctx, txnID, event.VerificationCancelCodeUser, "Recovery code preferred")
				assert.NoError(t, err)

				// The receiving device should not have a cancellation event.
				assert.Empty(t, ts.DeviceInbox[aliceUserID][receivingDeviceID])

				// Ensure that the cancellation event was sent to the sending device.
				assert.Len(t, ts.DeviceInbox[aliceUserID][sendingDeviceID], 1)
				cancelEvt = ts.DeviceInbox[aliceUserID][sendingDeviceID][0].Content.AsVerificationCancel()

				// The bystander device should not have a cancellation event.
				assert.Empty(t, ts.DeviceInbox[aliceUserID][bystanderDeviceID])
			}
			assert.Equal(t, txnID, cancelEvt.TransactionID)
			assert.Equal(t, event.VerificationCancelCodeUser, cancelEvt.Code)
			assert.Equal(t, "Recovery code preferred", cancelEvt.Reason)

			if !sendingCancels {
				// Process the cancellation event on the sending device.
				ts.DispatchToDevice(t, ctx, sendingClient)

				// Ensure that the cancellation event was sent to the bystander device.
				assert.Len(t, ts.DeviceInbox[aliceUserID][bystanderDeviceID], 1)
				bystanderCancelEvt := ts.DeviceInbox[aliceUserID][bystanderDeviceID][0].Content.AsVerificationCancel()
				assert.Equal(t, txnID, bystanderCancelEvt.TransactionID)
				assert.Equal(t, event.VerificationCancelCodeUser, bystanderCancelEvt.Code)
				assert.Equal(t, "The verification was rejected from another device.", bystanderCancelEvt.Reason)
			}
		})
	}
}

func TestVerification_Accept_NoSupportedMethods(t *testing.T) {
	ctx := log.Logger.WithContext(context.TODO())

	ts := mockserver.Create(t)

	sendingClient, sendingCryptoStore := ts.Login(t, ctx, aliceUserID, sendingDeviceID)
	receivingClient, _ := ts.Login(t, ctx, aliceUserID, receivingDeviceID)
	addDeviceID(ctx, sendingCryptoStore, aliceUserID, sendingDeviceID)
	addDeviceID(ctx, sendingCryptoStore, aliceUserID, receivingDeviceID)

	sendingMachine := sendingClient.Crypto.(*cryptohelper.CryptoHelper).Machine()
	recoveryKey, cache, err := sendingMachine.GenerateAndUploadCrossSigningKeys(ctx, nil, "")
	assert.NoError(t, err)
	assert.NotEmpty(t, recoveryKey)
	assert.NotNil(t, cache)

	sendingHelper := verificationhelper.NewVerificationHelper(sendingClient, sendingMachine, nil, newAllVerificationCallbacks(), true, true, true)
	err = sendingHelper.Init(ctx)
	require.NoError(t, err)

	receivingCallbacks := newBaseVerificationCallbacks()
	receivingHelper := verificationhelper.NewVerificationHelper(receivingClient, receivingClient.Crypto.(*cryptohelper.CryptoHelper).Machine(), nil, receivingCallbacks, false, false, false)
	err = receivingHelper.Init(ctx)
	require.NoError(t, err)

	txnID, err := sendingHelper.StartVerification(ctx, aliceUserID)
	require.NoError(t, err)
	require.NotEmpty(t, txnID)

	ts.DispatchToDevice(t, ctx, receivingClient)

	// Ensure that the receiver ignored the request because it
	// doesn't support any of the verification methods in the
	// request.
	assert.Empty(t, receivingCallbacks.GetRequestedVerifications())
}

func TestVerification_Accept_CorrectMethodsPresented(t *testing.T) {
	ctx := log.Logger.WithContext(context.TODO())

	testCases := []struct {
		sendingSupportsScan         bool
		sendingSupportsShow         bool
		receivingSupportsScan       bool
		receivingSupportsShow       bool
		sendingSupportsSAS          bool
		receivingSupportsSAS        bool
		sendingCallbacks            MockVerificationCallbacks
		receivingCallbacks          MockVerificationCallbacks
		expectedVerificationMethods []event.VerificationMethod
	}{
		// TODO
		{false, false, false, false, true, true, newSASVerificationCallbacks(), newSASVerificationCallbacks(), []event.VerificationMethod{event.VerificationMethodSAS}},
		{true, false, true, false, true, true, newSASVerificationCallbacks(), newSASVerificationCallbacks(), []event.VerificationMethod{event.VerificationMethodSAS}},

		{true, false, false, true, false, false, newShowQRCodeVerificationCallbacks(), newShowQRCodeVerificationCallbacks(), []event.VerificationMethod{event.VerificationMethodReciprocate, event.VerificationMethodQRCodeShow}},
		{false, true, true, false, false, false, newShowQRCodeVerificationCallbacks(), newShowQRCodeVerificationCallbacks(), []event.VerificationMethod{event.VerificationMethodReciprocate, event.VerificationMethodQRCodeScan}},
		{true, false, true, true, false, false, newShowQRCodeVerificationCallbacks(), newShowQRCodeVerificationCallbacks(), []event.VerificationMethod{event.VerificationMethodReciprocate, event.VerificationMethodQRCodeShow}},
		{false, true, true, true, false, false, newShowQRCodeVerificationCallbacks(), newShowQRCodeVerificationCallbacks(), []event.VerificationMethod{event.VerificationMethodReciprocate, event.VerificationMethodQRCodeScan}},
		{true, true, true, false, false, false, newShowQRCodeVerificationCallbacks(), newShowQRCodeVerificationCallbacks(), []event.VerificationMethod{event.VerificationMethodReciprocate, event.VerificationMethodQRCodeScan}},
		{true, true, false, true, false, false, newShowQRCodeVerificationCallbacks(), newShowQRCodeVerificationCallbacks(), []event.VerificationMethod{event.VerificationMethodReciprocate, event.VerificationMethodQRCodeShow}},
		{true, true, true, true, false, false, newShowQRCodeVerificationCallbacks(), newShowQRCodeVerificationCallbacks(), []event.VerificationMethod{event.VerificationMethodReciprocate, event.VerificationMethodQRCodeScan, event.VerificationMethodQRCodeShow}},

		{true, true, true, true, true, true, newAllVerificationCallbacks(), newAllVerificationCallbacks(), []event.VerificationMethod{event.VerificationMethodSAS, event.VerificationMethodReciprocate, event.VerificationMethodQRCodeScan, event.VerificationMethodQRCodeShow}},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			ts, sendingClient, receivingClient, _, _, sendingMachine, receivingMachine := initServerAndLoginTwoAlice(t, ctx)

			recoveryKey, sendingCrossSigningKeysCache, err := sendingMachine.GenerateAndUploadCrossSigningKeys(ctx, nil, "")
			assert.NoError(t, err)
			assert.NotEmpty(t, recoveryKey)
			assert.NotNil(t, sendingCrossSigningKeysCache)

			sendingHelper := verificationhelper.NewVerificationHelper(sendingClient, sendingMachine, nil, tc.sendingCallbacks, tc.sendingSupportsShow, tc.sendingSupportsScan, tc.sendingSupportsSAS)
			err = sendingHelper.Init(ctx)
			require.NoError(t, err)

			receivingHelper := verificationhelper.NewVerificationHelper(receivingClient, receivingMachine, nil, tc.receivingCallbacks, tc.receivingSupportsShow, tc.receivingSupportsScan, tc.receivingSupportsSAS)
			err = receivingHelper.Init(ctx)
			require.NoError(t, err)

			txnID, err := sendingHelper.StartVerification(ctx, aliceUserID)
			require.NoError(t, err)

			// Process the verification request on the receiving device.
			ts.DispatchToDevice(t, ctx, receivingClient)

			// Ensure that the receiving device received a verification
			// request with the correct transaction ID.
			assert.ElementsMatch(t, []id.VerificationTransactionID{txnID}, tc.receivingCallbacks.GetRequestedVerifications()[aliceUserID])

			// Have the receiving device accept the verification request.
			err = receivingHelper.AcceptVerification(ctx, txnID)
			require.NoError(t, err)

			// Ensure that the receiving device get a notification about the
			// transaction being ready.
			assert.Contains(t, tc.receivingCallbacks.GetVerificationsReadyTransactions(), txnID)

			// Ensure that if the receiving device should show a QR code that
			// it has the correct content.
			if tc.sendingSupportsScan && tc.receivingSupportsShow {
				receivingShownQRCode := tc.receivingCallbacks.GetQRCodeShown(txnID)
				require.NotNil(t, receivingShownQRCode)
				assert.Equal(t, txnID, receivingShownQRCode.TransactionID)
				assert.NotEmpty(t, receivingShownQRCode.SharedSecret)
			}

			// Check for whether the receiving device should be scanning a QR
			// code.
			if tc.receivingSupportsScan && tc.sendingSupportsShow {
				assert.Contains(t, tc.receivingCallbacks.GetScanQRCodeTransactions(), txnID)
			}

			// Check that the m.key.verification.ready event has the correct
			// content.
			sendingInbox := ts.DeviceInbox[aliceUserID][sendingDeviceID]
			assert.Len(t, sendingInbox, 1)
			readyEvt := sendingInbox[0].Content.AsVerificationReady()
			assert.Equal(t, txnID, readyEvt.TransactionID)
			assert.Equal(t, receivingDeviceID, readyEvt.FromDevice)
			assert.ElementsMatch(t, tc.expectedVerificationMethods, readyEvt.Methods)

			// Receive the m.key.verification.ready event on the sending
			// device.
			ts.DispatchToDevice(t, ctx, sendingClient)

			// Ensure that the sending device got a notification about the
			// transaction being ready.
			assert.Contains(t, tc.sendingCallbacks.GetVerificationsReadyTransactions(), txnID)

			// Ensure that if the sending device should show a QR code that it
			// has the correct content.
			if tc.receivingSupportsScan && tc.sendingSupportsShow {
				sendingShownQRCode := tc.sendingCallbacks.GetQRCodeShown(txnID)
				require.NotNil(t, sendingShownQRCode)
				assert.Equal(t, txnID, sendingShownQRCode.TransactionID)
				assert.NotEmpty(t, sendingShownQRCode.SharedSecret)
			}

			// Check for whether the sending device should be scanning a QR
			// code.
			if tc.sendingSupportsScan && tc.receivingSupportsShow {
				assert.Contains(t, tc.sendingCallbacks.GetScanQRCodeTransactions(), txnID)
			}
		})
	}
}

// TestAcceptSelfVerificationCancelOnNonParticipatingDevices ensures that we do
// not regress https://github.com/mautrix/go/pull/230.
func TestVerification_Accept_CancelOnNonParticipatingDevices(t *testing.T) {
	ctx := log.Logger.WithContext(context.TODO())
	ts, sendingClient, receivingClient, sendingCryptoStore, receivingCryptoStore, sendingMachine, receivingMachine := initServerAndLoginTwoAlice(t, ctx)
	_, _, sendingHelper, receivingHelper := initDefaultCallbacks(t, ctx, sendingClient, receivingClient, sendingMachine, receivingMachine)

	nonParticipatingDeviceID1 := id.DeviceID("non-participating1")
	nonParticipatingDeviceID2 := id.DeviceID("non-participating2")
	addDeviceID(ctx, sendingCryptoStore, aliceUserID, nonParticipatingDeviceID1)
	addDeviceID(ctx, sendingCryptoStore, aliceUserID, nonParticipatingDeviceID2)
	addDeviceID(ctx, receivingCryptoStore, aliceUserID, nonParticipatingDeviceID1)
	addDeviceID(ctx, receivingCryptoStore, aliceUserID, nonParticipatingDeviceID2)

	_, _, err := sendingMachine.GenerateAndUploadCrossSigningKeys(ctx, nil, "")
	assert.NoError(t, err)

	// Send the verification request from the sender device and accept it on
	// the receiving device.
	txnID, err := sendingHelper.StartVerification(ctx, aliceUserID)
	require.NoError(t, err)
	ts.DispatchToDevice(t, ctx, receivingClient)
	err = receivingHelper.AcceptVerification(ctx, txnID)
	require.NoError(t, err)

	// Receive the m.key.verification.ready event on the sending device.
	ts.DispatchToDevice(t, ctx, sendingClient)

	// The sending and receiving devices should not have any cancellation
	// events in their inboxes.
	assert.Empty(t, ts.DeviceInbox[aliceUserID][sendingDeviceID])
	assert.Empty(t, ts.DeviceInbox[aliceUserID][receivingDeviceID])

	// There should now be cancellation events in the non-participating devices
	// inboxes (in addition to the request event).
	assert.Len(t, ts.DeviceInbox[aliceUserID][nonParticipatingDeviceID1], 2)
	assert.Len(t, ts.DeviceInbox[aliceUserID][nonParticipatingDeviceID2], 2)
	assert.Equal(t, ts.DeviceInbox[aliceUserID][nonParticipatingDeviceID1][1], ts.DeviceInbox[aliceUserID][nonParticipatingDeviceID2][1])
	cancellationEvent := ts.DeviceInbox[aliceUserID][nonParticipatingDeviceID1][1].Content.AsVerificationCancel()
	assert.Equal(t, txnID, cancellationEvent.TransactionID)
	assert.Equal(t, event.VerificationCancelCodeAccepted, cancellationEvent.Code)
}

func TestVerification_ErrorOnDoubleAccept(t *testing.T) {
	ctx := log.Logger.WithContext(context.TODO())
	ts, sendingClient, receivingClient, _, _, sendingMachine, receivingMachine := initServerAndLoginTwoAlice(t, ctx)
	_, _, sendingHelper, receivingHelper := initDefaultCallbacks(t, ctx, sendingClient, receivingClient, sendingMachine, receivingMachine)

	_, _, err := sendingMachine.GenerateAndUploadCrossSigningKeys(ctx, nil, "")
	require.NoError(t, err)

	txnID, err := sendingHelper.StartVerification(ctx, aliceUserID)
	require.NoError(t, err)
	ts.DispatchToDevice(t, ctx, receivingClient)
	err = receivingHelper.AcceptVerification(ctx, txnID)
	require.NoError(t, err)
	err = receivingHelper.AcceptVerification(ctx, txnID)
	assert.ErrorContains(t, err, "transaction is not in the requested state")
}

// TestVerification_CancelOnDoubleStart ensures that the receiving device
// cancels both transactions if the sending device starts two verifications.
//
// This test ensures that the following bullet point from [Section 10.12.2.2.1
// of the Spec] is followed:
//
//   - When the same device attempts to initiate multiple verification attempts,
//     the recipient should cancel all attempts with that device.
//
// [Section 10.12.2.2.1 of the Spec]: https://spec.matrix.org/v1.10/client-server-api/#error-and-exception-handling
func TestVerification_CancelOnDoubleStart(t *testing.T) {
	ctx := log.Logger.WithContext(context.TODO())
	ts, sendingClient, receivingClient, _, _, sendingMachine, receivingMachine := initServerAndLoginTwoAlice(t, ctx)
	sendingCallbacks, receivingCallbacks, sendingHelper, receivingHelper := initDefaultCallbacks(t, ctx, sendingClient, receivingClient, sendingMachine, receivingMachine)

	_, _, err := sendingMachine.GenerateAndUploadCrossSigningKeys(ctx, nil, "")
	require.NoError(t, err)

	// Send and accept the first verification request.
	txnID1, err := sendingHelper.StartVerification(ctx, aliceUserID)
	require.NoError(t, err)
	ts.DispatchToDevice(t, ctx, receivingClient)
	err = receivingHelper.AcceptVerification(ctx, txnID1)
	require.NoError(t, err)
	ts.DispatchToDevice(t, ctx, sendingClient) // Process the m.key.verification.ready event

	// Send a second verification request
	txnID2, err := sendingHelper.StartVerification(ctx, aliceUserID)
	require.NoError(t, err)
	ts.DispatchToDevice(t, ctx, receivingClient)

	// Ensure that the sending device received a cancellation event for both of
	// the ongoing transactions.
	sendingInbox := ts.DeviceInbox[aliceUserID][sendingDeviceID]
	require.Len(t, sendingInbox, 2)
	cancelEvt1 := sendingInbox[0].Content.AsVerificationCancel()
	cancelEvt2 := sendingInbox[1].Content.AsVerificationCancel()
	cancelledTxnIDs := []id.VerificationTransactionID{cancelEvt1.TransactionID, cancelEvt2.TransactionID}
	assert.Contains(t, cancelledTxnIDs, txnID1)
	assert.Contains(t, cancelledTxnIDs, txnID2)
	assert.Equal(t, event.VerificationCancelCodeUnexpectedMessage, cancelEvt1.Code)
	assert.Equal(t, event.VerificationCancelCodeUnexpectedMessage, cancelEvt2.Code)
	assert.Equal(t, "received multiple verification requests from the same device", cancelEvt1.Reason)
	assert.Equal(t, "received multiple verification requests from the same device", cancelEvt2.Reason)

	assert.NotNil(t, receivingCallbacks.GetVerificationCancellation(txnID1))
	assert.NotNil(t, receivingCallbacks.GetVerificationCancellation(txnID2))
	ts.DispatchToDevice(t, ctx, sendingClient) // Process the m.key.verification.cancel events
	assert.NotNil(t, sendingCallbacks.GetVerificationCancellation(txnID1))
	assert.NotNil(t, sendingCallbacks.GetVerificationCancellation(txnID2))
}
