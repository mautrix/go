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

var aliceUserID = id.UserID("@alice:example.org")
var bobUserID = id.UserID("@bob:example.org")
var sendingDeviceID = id.DeviceID("sending")
var receivingDeviceID = id.DeviceID("receiving")

func init() {
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).With().Timestamp().Logger().Level(zerolog.TraceLevel)
	zerolog.DefaultContextLogger = &log.Logger
}

func initServerAndLoginTwoAlice(t *testing.T, ctx context.Context) (ts *mockServer, sendingClient, receivingClient *mautrix.Client, sendingCryptoStore, receivingCryptoStore crypto.Store, sendingMachine, receivingMachine *crypto.OlmMachine) {
	t.Helper()
	ts = createMockServer(t)

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

func initServerAndLoginAliceBob(t *testing.T, ctx context.Context) (ts *mockServer, sendingClient, receivingClient *mautrix.Client, sendingCryptoStore, receivingCryptoStore crypto.Store, sendingMachine, receivingMachine *crypto.OlmMachine) {
	t.Helper()
	ts = createMockServer(t)

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
	sendingHelper = verificationhelper.NewVerificationHelper(sendingClient, sendingMachine, sendingCallbacks, true)
	require.NoError(t, sendingHelper.Init(ctx))

	receivingCallbacks = newAllVerificationCallbacks()
	receivingHelper = verificationhelper.NewVerificationHelper(receivingClient, receivingMachine, receivingCallbacks, true)
	require.NoError(t, receivingHelper.Init(ctx))
	return
}

func TestVerification_Start(t *testing.T) {
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

			client, cryptoStore := ts.Login(t, ctx, aliceUserID, sendingDeviceID)
			addDeviceID(ctx, cryptoStore, aliceUserID, sendingDeviceID)
			addDeviceID(ctx, cryptoStore, aliceUserID, receivingDeviceID)
			addDeviceID(ctx, cryptoStore, aliceUserID, receivingDeviceID2)

			senderHelper := verificationhelper.NewVerificationHelper(client, client.Crypto.(*cryptohelper.CryptoHelper).Machine(), tc.callbacks, tc.supportsScan)
			err := senderHelper.Init(ctx)
			require.NoError(t, err)

			txnID, err := senderHelper.StartVerification(ctx, aliceUserID)
			if tc.startVerificationErrMsg != "" {
				assert.ErrorContains(t, err, tc.startVerificationErrMsg)
				return
			}

			assert.NoError(t, err)
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
			assert.Len(t, toDeviceInbox[receivingDeviceID], 1)

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

	for _, sendingCancels := range []bool{true, false} {
		t.Run(fmt.Sprintf("sendingCancels=%t", sendingCancels), func(t *testing.T) {
			ts, sendingClient, receivingClient, _, _, sendingMachine, receivingMachine := initServerAndLoginTwoAlice(t, ctx)
			defer ts.Close()
			_, _, sendingHelper, receivingHelper := initDefaultCallbacks(t, ctx, sendingClient, receivingClient, sendingMachine, receivingMachine)

			txnID, err := sendingHelper.StartVerification(ctx, aliceUserID)
			require.NoError(t, err)

			assert.Empty(t, ts.DeviceInbox[aliceUserID][sendingDeviceID])

			// Process the request event on the receiving device.
			receivingInbox := ts.DeviceInbox[aliceUserID][receivingDeviceID]
			assert.Len(t, receivingInbox, 1)
			assert.Equal(t, txnID, receivingInbox[0].Content.AsVerificationRequest().TransactionID)
			ts.dispatchToDevice(t, ctx, receivingClient)

			// Cancel the verification request on the sending device.
			var cancelEvt *event.VerificationCancelEventContent
			if sendingCancels {
				err = sendingHelper.CancelVerification(ctx, txnID, event.VerificationCancelCodeUser, "Recovery code preferred")
				assert.NoError(t, err)

				// The sending device should not have a cancellation event.
				assert.Empty(t, ts.DeviceInbox[aliceUserID][sendingDeviceID])

				// Ensure that the cancellation event was sent to the receiving device.
				assert.Len(t, ts.DeviceInbox[aliceUserID][receivingDeviceID], 1)
				cancelEvt = ts.DeviceInbox[aliceUserID][receivingDeviceID][0].Content.AsVerificationCancel()
			} else {
				err = receivingHelper.CancelVerification(ctx, txnID, event.VerificationCancelCodeUser, "Recovery code preferred")
				assert.NoError(t, err)

				// The receiving device should not have a cancellation event.
				assert.Empty(t, ts.DeviceInbox[aliceUserID][receivingDeviceID])

				// Ensure that the cancellation event was sent to the sending device.
				assert.Len(t, ts.DeviceInbox[aliceUserID][sendingDeviceID], 1)
				cancelEvt = ts.DeviceInbox[aliceUserID][sendingDeviceID][0].Content.AsVerificationCancel()
			}
			assert.Equal(t, txnID, cancelEvt.TransactionID)
			assert.Equal(t, event.VerificationCancelCodeUser, cancelEvt.Code)
			assert.Equal(t, "Recovery code preferred", cancelEvt.Reason)
		})
	}
}

func TestVerification_Accept_NoSupportedMethods(t *testing.T) {
	ctx := log.Logger.WithContext(context.TODO())

	ts := createMockServer(t)
	defer ts.Close()

	sendingClient, sendingCryptoStore := ts.Login(t, ctx, aliceUserID, sendingDeviceID)
	receivingClient, _ := ts.Login(t, ctx, aliceUserID, receivingDeviceID)
	addDeviceID(ctx, sendingCryptoStore, aliceUserID, sendingDeviceID)
	addDeviceID(ctx, sendingCryptoStore, aliceUserID, receivingDeviceID)

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

	txnID, err := sendingHelper.StartVerification(ctx, aliceUserID)
	require.NoError(t, err)
	require.NotEmpty(t, txnID)

	ts.dispatchToDevice(t, ctx, receivingClient)

	// Ensure that the receiver ignored the request because it
	// doesn't support any of the verification methods in the
	// request.
	assert.Empty(t, receivingCallbacks.GetRequestedVerifications())
}

func TestVerification_Accept_CorrectMethodsPresented(t *testing.T) {
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
			ts, sendingClient, receivingClient, _, _, sendingMachine, receivingMachine := initServerAndLoginTwoAlice(t, ctx)
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

			txnID, err := sendingHelper.StartVerification(ctx, aliceUserID)
			require.NoError(t, err)

			// Process the verification request on the receiving device.
			ts.dispatchToDevice(t, ctx, receivingClient)

			// Ensure that the receiving device received a verification
			// request with the correct transaction ID.
			assert.ElementsMatch(t, []id.VerificationTransactionID{txnID}, tc.receivingCallbacks.GetRequestedVerifications()[aliceUserID])

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
			sendingInbox := ts.DeviceInbox[aliceUserID][sendingDeviceID]
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

// TestAcceptSelfVerificationCancelOnNonParticipatingDevices ensures that we do
// not regress https://github.com/mautrix/go/pull/230.
func TestVerification_Accept_CancelOnNonParticipatingDevices(t *testing.T) {
	ctx := log.Logger.WithContext(context.TODO())
	ts, sendingClient, receivingClient, sendingCryptoStore, receivingCryptoStore, sendingMachine, receivingMachine := initServerAndLoginTwoAlice(t, ctx)
	defer ts.Close()
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
	ts.dispatchToDevice(t, ctx, receivingClient)
	err = receivingHelper.AcceptVerification(ctx, txnID)
	require.NoError(t, err)

	// Receive the m.key.verification.ready event on the sending device.
	ts.dispatchToDevice(t, ctx, sendingClient)

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
	defer ts.Close()
	_, _, sendingHelper, receivingHelper := initDefaultCallbacks(t, ctx, sendingClient, receivingClient, sendingMachine, receivingMachine)

	_, _, err := sendingMachine.GenerateAndUploadCrossSigningKeys(ctx, nil, "")
	require.NoError(t, err)

	txnID, err := sendingHelper.StartVerification(ctx, aliceUserID)
	require.NoError(t, err)
	ts.dispatchToDevice(t, ctx, receivingClient)
	err = receivingHelper.AcceptVerification(ctx, txnID)
	require.NoError(t, err)
	err = receivingHelper.AcceptVerification(ctx, txnID)
	require.ErrorContains(t, err, "transaction is not in the requested state")
}
