package verificationhelper_test

import (
	"context"
	"testing"

	"github.com/rs/zerolog/log" // zerolog-allow-global-log
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mau.fi/util/jsonbytes"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func sendRawToDevice(t *testing.T, ctx context.Context, from *mautrix.Client, toUser id.UserID, toDevice id.DeviceID, evtType event.Type, content any) {
	t.Helper()
	_, err := from.SendToDevice(ctx, evtType, &mautrix.ReqSendToDevice{
		Messages: map[id.UserID]map[id.DeviceID]*event.Content{
			toUser: {toDevice: {Parsed: content}},
		},
	})
	require.NoError(t, err)
}

func TestVerification_UnexpectedMAC(t *testing.T) {
	ctx := log.Logger.WithContext(context.TODO())

	testCases := map[string]bool{
		"requested": false,
		"ready":     true,
	}
	for name, accept := range testCases {
		t.Run(name, func(t *testing.T) {
			ts, sendingClient, receivingClient, _, _, sendingMachine, receivingMachine := initServerAndLoginTwoAlice(t, ctx)
			_, receivingCallbacks, sendingHelper, receivingHelper := initDefaultCallbacks(t, ctx, sendingClient, receivingClient, sendingMachine, receivingMachine)

			_, _, err := sendingMachine.GenerateAndUploadCrossSigningKeys(ctx, nil, "")
			require.NoError(t, err)

			txnID, err := sendingHelper.StartVerification(ctx, aliceUserID)
			require.NoError(t, err)
			ts.DispatchToDevice(t, ctx, receivingClient)
			if accept {
				require.NoError(t, receivingHelper.AcceptVerification(ctx, txnID))
				ts.DeviceInbox[aliceUserID][sendingDeviceID] = nil
			}

			sendRawToDevice(t, ctx, sendingClient, aliceUserID, receivingDeviceID, event.ToDeviceVerificationMAC, &event.VerificationMACEventContent{
				ToDeviceVerificationEvent: event.ToDeviceVerificationEvent{TransactionID: txnID},
				Keys:                      []byte("keys"),
				MAC: map[id.KeyID]jsonbytes.UnpaddedBytes{
					id.NewKeyID(id.KeyAlgorithmEd25519, sendingDeviceID.String()): []byte("mac"),
				},
			})
			assert.NotPanics(t, func() {
				ts.DispatchToDevice(t, ctx, receivingClient)
			})

			cancellation := receivingCallbacks.GetVerificationCancellation(txnID)
			require.NotNil(t, cancellation)
			assert.Equal(t, event.VerificationCancelCodeUnexpectedMessage, cancellation.Code)
		})
	}
}

func TestVerification_UnexpectedKey(t *testing.T) {
	ctx := log.Logger.WithContext(context.TODO())
	ts, sendingClient, receivingClient, _, _, sendingMachine, receivingMachine := initServerAndLoginTwoAlice(t, ctx)
	_, receivingCallbacks, sendingHelper, receivingHelper := initDefaultCallbacks(t, ctx, sendingClient, receivingClient, sendingMachine, receivingMachine)

	_, _, err := sendingMachine.GenerateAndUploadCrossSigningKeys(ctx, nil, "")
	require.NoError(t, err)

	txnID, err := sendingHelper.StartVerification(ctx, aliceUserID)
	require.NoError(t, err)
	ts.DispatchToDevice(t, ctx, receivingClient)
	require.NoError(t, receivingHelper.AcceptVerification(ctx, txnID))

	sendRawToDevice(t, ctx, sendingClient, aliceUserID, receivingDeviceID, event.ToDeviceVerificationKey, &event.VerificationKeyEventContent{
		ToDeviceVerificationEvent: event.ToDeviceVerificationEvent{TransactionID: txnID},
		Key:                       make([]byte, 32),
	})
	assert.NotPanics(t, func() {
		ts.DispatchToDevice(t, ctx, receivingClient)
	})
	cancellation := receivingCallbacks.GetVerificationCancellation(txnID)
	require.NotNil(t, cancellation)
	assert.Equal(t, event.VerificationCancelCodeUnexpectedMessage, cancellation.Code)
}

func TestVerification_IgnoreEventsFromOtherUsers(t *testing.T) {
	ctx := log.Logger.WithContext(context.TODO())
	ts, sendingClient, receivingClient, _, _, sendingMachine, receivingMachine := initServerAndLoginTwoAlice(t, ctx)
	_, receivingCallbacks, sendingHelper, _ := initDefaultCallbacks(t, ctx, sendingClient, receivingClient, sendingMachine, receivingMachine)
	bobClient, _ := ts.Login(t, ctx, bobUserID, "bob")

	txnID, err := sendingHelper.StartVerification(ctx, aliceUserID)
	require.NoError(t, err)
	ts.DispatchToDevice(t, ctx, receivingClient)

	sendRawToDevice(t, ctx, bobClient, aliceUserID, receivingDeviceID, event.ToDeviceVerificationCancel, &event.VerificationCancelEventContent{
		ToDeviceVerificationEvent: event.ToDeviceVerificationEvent{TransactionID: txnID},
		Code:                      event.VerificationCancelCodeUser,
		Reason:                    "not your transaction",
	})
	ts.DispatchToDevice(t, ctx, receivingClient)
	assert.Nil(t, receivingCallbacks.GetVerificationCancellation(txnID))
}
