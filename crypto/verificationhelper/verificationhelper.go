// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package verificationhelper

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"fmt"
	"sync"

	"github.com/rs/zerolog"
	"go.mau.fi/util/jsontime"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type verificationState int

const (
	verificationStateRequested verificationState = iota
	verificationStateReady
	verificationStateCancelled
	verificationStateDone

	verificationStateTheirQRScanned // We scanned their QR code
	verificationStateOurQRScanned   // They scanned our QR code

	verificationStateSASStarted       // An SAS verification has been started
	verificationStateSASAccepted      // An SAS verification has been accepted
	verificationStateSASKeysExchanged // An SAS verification has exchanged keys
	verificationStateSASMACExchanged  // An SAS verification has exchanged MACs
)

func (step verificationState) String() string {
	switch step {
	case verificationStateRequested:
		return "requested"
	case verificationStateReady:
		return "ready"
	case verificationStateCancelled:
		return "cancelled"
	case verificationStateTheirQRScanned:
		return "their_qr_scanned"
	case verificationStateOurQRScanned:
		return "our_qr_scanned"
	case verificationStateSASStarted:
		return "sas_started"
	case verificationStateSASAccepted:
		return "sas_accepted"
	case verificationStateSASKeysExchanged:
		return "sas_keys_exchanged"
	case verificationStateSASMACExchanged:
		return "sas_mac"
	default:
		return fmt.Sprintf("verificationStep(%d)", step)
	}
}

type verificationTransaction struct {
	// RoomID is the room ID if the verification is happening in a room or
	// empty if it is a to-device verification.
	RoomID id.RoomID

	// VerificationState is the current step of the verification flow.
	VerificationState verificationState
	// TransactionID is the ID of the verification transaction.
	TransactionID id.VerificationTransactionID

	// TheirDevice is the device ID of the device that either made the initial
	// request or accepted our request.
	TheirDevice id.DeviceID
	// TheirUser is the user ID of the other user.
	TheirUser id.UserID
	// TheirSupportedMethods is a list of verification methods that the other
	// device supports.
	TheirSupportedMethods []event.VerificationMethod

	// SentToDeviceIDs is a list of devices which the initial request was sent
	// to. This is only used for to-device verification requests, and is meant
	// to be used to send cancellation requests to all other devices when a
	// verification request is accepted via a m.key.verification.ready event.
	SentToDeviceIDs []id.DeviceID

	// QRCodeSharedSecret is the shared secret that was encoded in the QR code
	// that we showed.
	QRCodeSharedSecret []byte

	StartedByUs              bool                                 // Whether the verification was started by us
	StartEventContent        *event.VerificationStartEventContent // The m.key.verification.start event content
	Commitment               []byte                               // The commitment from the m.key.verification.accept event
	MACMethod                event.MACMethod                      // The method used to calculate the MAC
	EphemeralKey             *ecdh.PrivateKey                     // The ephemeral key
	EphemeralPublicKeyShared bool                                 // Whether this device's ephemeral public key has been shared
	OtherPublicKey           *ecdh.PublicKey                      // The other device's ephemeral public key
	ReceivedTheirMAC         bool                                 // Whether we have received their MAC
	SentOurMAC               bool                                 // Whether we have sent our MAC
	ReceivedTheirDone        bool                                 // Whether we have received their done event
	SentOurDone              bool                                 // Whether we have sent our done event
}

// RequiredCallbacks is an interface representing the callbacks required for
// the [VerificationHelper].
type RequiredCallbacks interface {
	// VerificationRequested is called when a verification request is received
	// from another device.
	VerificationRequested(ctx context.Context, txnID id.VerificationTransactionID, from id.UserID)

	// VerificationCancelled is called when the verification is cancelled.
	VerificationCancelled(ctx context.Context, txnID id.VerificationTransactionID, code event.VerificationCancelCode, reason string)

	// VerificationDone is called when the verification is done.
	VerificationDone(ctx context.Context, txnID id.VerificationTransactionID)
}

type showSASCallbacks interface {
	// ShowSAS is a callback that is called when the SAS verification has
	// generated a short authentication string to show. It is guaranteed that
	// either the emojis list, or the decimals list, or both will be present.
	ShowSAS(ctx context.Context, txnID id.VerificationTransactionID, emojis []rune, decimals []int)
}

type showQRCodeCallbacks interface {
	// ScanQRCode is called when another device has sent a
	// m.key.verification.ready event and indicated that they are capable of
	// showing a QR code.
	ScanQRCode(ctx context.Context, txnID id.VerificationTransactionID)

	// ShowQRCode is called when the verification has been accepted and a QR
	// code should be shown to the user.
	ShowQRCode(ctx context.Context, txnID id.VerificationTransactionID, qrCode *QRCode)

	// QRCodeScanned is called when the other user has scanned the QR code and
	// sent the m.key.verification.start event.
	QRCodeScanned(ctx context.Context, txnID id.VerificationTransactionID)
}

type VerificationHelper struct {
	client *mautrix.Client
	mach   *crypto.OlmMachine

	activeTransactions     map[id.VerificationTransactionID]*verificationTransaction
	activeTransactionsLock sync.Mutex

	// supportedMethods are the methods that *we* support
	supportedMethods              []event.VerificationMethod
	verificationRequested         func(ctx context.Context, txnID id.VerificationTransactionID, from id.UserID)
	verificationCancelledCallback func(ctx context.Context, txnID id.VerificationTransactionID, code event.VerificationCancelCode, reason string)
	verificationDone              func(ctx context.Context, txnID id.VerificationTransactionID)

	showSAS func(ctx context.Context, txnID id.VerificationTransactionID, emojis []rune, decimals []int)

	scanQRCode   func(ctx context.Context, txnID id.VerificationTransactionID)
	showQRCode   func(ctx context.Context, txnID id.VerificationTransactionID, qrCode *QRCode)
	qrCodeScaned func(ctx context.Context, txnID id.VerificationTransactionID)
}

var _ mautrix.VerificationHelper = (*VerificationHelper)(nil)

func NewVerificationHelper(client *mautrix.Client, mach *crypto.OlmMachine, callbacks any, supportsScan bool) *VerificationHelper {
	if client.Crypto == nil {
		panic("client.Crypto is nil")
	}

	helper := VerificationHelper{
		client:             client,
		mach:               mach,
		activeTransactions: map[id.VerificationTransactionID]*verificationTransaction{},
	}

	if c, ok := callbacks.(RequiredCallbacks); !ok {
		panic("callbacks must implement VerificationRequested")
	} else {
		helper.verificationRequested = c.VerificationRequested
		helper.verificationCancelledCallback = c.VerificationCancelled
		helper.verificationDone = c.VerificationDone
	}

	if c, ok := callbacks.(showSASCallbacks); ok {
		helper.supportedMethods = append(helper.supportedMethods, event.VerificationMethodSAS)
		helper.showSAS = c.ShowSAS
	}
	if c, ok := callbacks.(showQRCodeCallbacks); ok {
		helper.supportedMethods = append(helper.supportedMethods,
			event.VerificationMethodQRCodeShow, event.VerificationMethodReciprocate)
		helper.scanQRCode = c.ScanQRCode
		helper.showQRCode = c.ShowQRCode
		helper.qrCodeScaned = c.QRCodeScanned
	}
	if supportsScan {
		helper.supportedMethods = append(helper.supportedMethods,
			event.VerificationMethodQRCodeScan, event.VerificationMethodReciprocate)
	}

	slices.Sort(helper.supportedMethods)
	helper.supportedMethods = slices.Compact(helper.supportedMethods)
	return &helper
}

func (vh *VerificationHelper) getLog(ctx context.Context) *zerolog.Logger {
	logger := zerolog.Ctx(ctx).With().
		Str("component", "verification").
		Any("supported_methods", vh.supportedMethods).
		Logger()
	return &logger
}

// Init initializes the verification helper by adding the necessary event
// handlers to the syncer.
func (vh *VerificationHelper) Init(ctx context.Context) error {
	if vh == nil {
		return fmt.Errorf("verification helper is nil")
	}
	syncer, ok := vh.client.Syncer.(mautrix.ExtensibleSyncer)
	if !ok {
		return fmt.Errorf("the client syncer must implement ExtensibleSyncer")
	}

	// Event handlers for verification requests. These are special since we do
	// not need to check that the transaction ID is known.
	syncer.OnEventType(event.ToDeviceVerificationRequest, vh.onVerificationRequest)
	syncer.OnEventType(event.EventMessage, func(ctx context.Context, evt *event.Event) {
		if evt.Content.AsMessage().MsgType == event.MsgVerificationRequest {
			vh.onVerificationRequest(ctx, evt)
		}
	})

	// Wrapper for the event handlers to check that the transaction ID is known
	// and ignore the event if it isn't.
	wrapHandler := func(callback func(context.Context, *verificationTransaction, *event.Event)) func(context.Context, *event.Event) {
		return func(ctx context.Context, evt *event.Event) {
			log := vh.getLog(ctx).With().
				Str("verification_action", "check transaction ID").
				Stringer("sender", evt.Sender).
				Stringer("room_id", evt.RoomID).
				Stringer("event_id", evt.ID).
				Logger()

			var transactionID id.VerificationTransactionID
			if evt.ID != "" {
				transactionID = id.VerificationTransactionID(evt.ID)
			} else {
				txnID, ok := evt.Content.Raw["transaction_id"].(string)
				if !ok {
					log.Warn().Msg("Ignoring verification event without a transaction ID")
					return
				}
				transactionID = id.VerificationTransactionID(txnID)
			}
			log = log.With().Stringer("transaction_id", transactionID).Logger()

			vh.activeTransactionsLock.Lock()
			txn, ok := vh.activeTransactions[transactionID]
			vh.activeTransactionsLock.Unlock()
			if !ok || txn.VerificationState == verificationStateCancelled || txn.VerificationState == verificationStateDone {
				var code event.VerificationCancelCode
				var reason string
				if !ok {
					log.Warn().Msg("Ignoring verification event for an unknown transaction and sending cancellation")

					// We have to create a fake transaction so that the call to
					// verificationCancelled works.
					txn = &verificationTransaction{
						RoomID:    evt.RoomID,
						TheirUser: evt.Sender,
					}
					txn.TransactionID = evt.Content.Parsed.(event.VerificationTransactionable).GetTransactionID()
					if txn.TransactionID == "" {
						txn.TransactionID = id.VerificationTransactionID(evt.ID)
					}
					if fromDevice, ok := evt.Content.Raw["from_device"]; ok {
						txn.TheirDevice = id.DeviceID(fromDevice.(string))
					}
					code = event.VerificationCancelCodeUnknownTransaction
					reason = "The transaction ID was not recognized."
				} else if txn.VerificationState == verificationStateCancelled {
					log.Warn().Msg("Ignoring verification event for a cancelled transaction")
					code = event.VerificationCancelCodeUnexpectedMessage
					reason = "The transaction is cancelled."
				} else if txn.VerificationState == verificationStateDone {
					code = event.VerificationCancelCodeUnexpectedMessage
					reason = "The transaction is done."
				}

				// Send the actual cancellation event.
				vh.cancelVerificationTxn(ctx, txn, code, reason)
				return
			}

			logCtx := vh.getLog(ctx).With().
				Stringer("transaction_step", txn.VerificationState).
				Stringer("sender", evt.Sender)
			if evt.RoomID != "" {
				logCtx = logCtx.
					Stringer("room_id", evt.RoomID).
					Stringer("event_id", evt.ID)
			}
			callback(logCtx.Logger().WithContext(ctx), txn, evt)
		}
	}

	// Event handlers for the to-device verification events.
	syncer.OnEventType(event.ToDeviceVerificationReady, wrapHandler(vh.onVerificationReady))
	syncer.OnEventType(event.ToDeviceVerificationStart, wrapHandler(vh.onVerificationStart))
	syncer.OnEventType(event.ToDeviceVerificationDone, wrapHandler(vh.onVerificationDone))
	syncer.OnEventType(event.ToDeviceVerificationCancel, wrapHandler(vh.onVerificationCancel))
	syncer.OnEventType(event.ToDeviceVerificationAccept, wrapHandler(vh.onVerificationAccept)) // SAS
	syncer.OnEventType(event.ToDeviceVerificationKey, wrapHandler(vh.onVerificationKey))       // SAS
	syncer.OnEventType(event.ToDeviceVerificationMAC, wrapHandler(vh.onVerificationMAC))       // SAS

	// Event handlers for the in-room verification events.
	syncer.OnEventType(event.InRoomVerificationReady, wrapHandler(vh.onVerificationReady))
	syncer.OnEventType(event.InRoomVerificationStart, wrapHandler(vh.onVerificationStart))
	syncer.OnEventType(event.InRoomVerificationDone, wrapHandler(vh.onVerificationDone))
	syncer.OnEventType(event.InRoomVerificationCancel, wrapHandler(vh.onVerificationCancel))
	syncer.OnEventType(event.InRoomVerificationAccept, wrapHandler(vh.onVerificationAccept)) // SAS
	syncer.OnEventType(event.InRoomVerificationKey, wrapHandler(vh.onVerificationKey))       // SAS
	syncer.OnEventType(event.InRoomVerificationMAC, wrapHandler(vh.onVerificationMAC))       // SAS

	return nil
}

// StartVerification starts an interactive verification flow with the given
// user via a to-device event.
func (vh *VerificationHelper) StartVerification(ctx context.Context, to id.UserID) (id.VerificationTransactionID, error) {
	txnID := id.NewVerificationTransactionID()

	devices, err := vh.mach.CryptoStore.GetDevices(ctx, to)
	if err != nil {
		return "", fmt.Errorf("failed to get devices for user: %w", err)
	} else if len(devices) == 0 {
		// HACK: we are doing this because the client doesn't wait until it has
		// the devices before starting verification.
		if keys, err := vh.mach.FetchKeys(ctx, []id.UserID{to}, true); err != nil {
			return "", err
		} else {
			devices = keys[to]
		}
	}

	vh.getLog(ctx).Info().
		Str("verification_action", "start verification").
		Stringer("transaction_id", txnID).
		Stringer("to", to).
		Any("device_ids", maps.Keys(devices)).
		Msg("Sending verification request")

	content := &event.Content{
		Parsed: &event.VerificationRequestEventContent{
			ToDeviceVerificationEvent: event.ToDeviceVerificationEvent{TransactionID: txnID},
			FromDevice:                vh.client.DeviceID,
			Methods:                   vh.supportedMethods,
			Timestamp:                 jsontime.UnixMilliNow(),
		},
	}

	req := mautrix.ReqSendToDevice{Messages: map[id.UserID]map[id.DeviceID]*event.Content{to: {}}}
	for deviceID := range devices {
		if deviceID == vh.client.DeviceID {
			// Don't ever send the event to the current device. We are likely
			// trying to send a verification request to our other devices.
			continue
		}

		req.Messages[to][deviceID] = content
	}
	_, err = vh.client.SendToDevice(ctx, event.ToDeviceVerificationRequest, &req)
	if err != nil {
		return "", fmt.Errorf("failed to send verification request: %w", err)
	}

	vh.activeTransactionsLock.Lock()
	defer vh.activeTransactionsLock.Unlock()
	vh.activeTransactions[txnID] = &verificationTransaction{
		VerificationState: verificationStateRequested,
		TransactionID:     txnID,
		TheirUser:         to,
		SentToDeviceIDs:   maps.Keys(devices),
	}
	return txnID, nil
}

// StartVerification starts an interactive verification flow with the given
// user in the given room.
func (vh *VerificationHelper) StartInRoomVerification(ctx context.Context, roomID id.RoomID, to id.UserID) (id.VerificationTransactionID, error) {
	log := vh.getLog(ctx).With().
		Str("verification_action", "start in-room verification").
		Stringer("room_id", roomID).
		Stringer("to", to).
		Logger()

	log.Info().Msg("Sending verification request")
	content := event.MessageEventContent{
		MsgType:    event.MsgVerificationRequest,
		Body:       "Alice is requesting to verify your device, but your client does not support verification, so you may need to use a different verification method.",
		FromDevice: vh.client.DeviceID,
		Methods:    vh.supportedMethods,
		To:         to,
	}
	encryptedContent, err := vh.client.Crypto.Encrypt(ctx, roomID, event.EventMessage, &content)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt verification request: %w", err)
	}
	resp, err := vh.client.SendMessageEvent(ctx, roomID, event.EventMessage, encryptedContent)
	if err != nil {
		return "", fmt.Errorf("failed to send verification request: %w", err)
	}

	txnID := id.VerificationTransactionID(resp.EventID)
	log.Info().Stringer("transaction_id", txnID).Msg("Got a transaction ID for the verification request")

	vh.activeTransactionsLock.Lock()
	defer vh.activeTransactionsLock.Unlock()
	vh.activeTransactions[txnID] = &verificationTransaction{
		RoomID:            roomID,
		VerificationState: verificationStateRequested,
		TransactionID:     txnID,
		TheirUser:         to,
	}
	return txnID, nil
}

// AcceptVerification accepts a verification request. The transaction ID should
// be the transaction ID of a verification request that was received via the
// VerificationRequested callback in [RequiredCallbacks].
func (vh *VerificationHelper) AcceptVerification(ctx context.Context, txnID id.VerificationTransactionID) error {
	log := vh.getLog(ctx).With().
		Str("verification_action", "accept verification").
		Stringer("transaction_id", txnID).
		Logger()

	txn, ok := vh.activeTransactions[txnID]
	if !ok {
		return fmt.Errorf("unknown transaction ID")
	}
	if txn.VerificationState != verificationStateRequested {
		return fmt.Errorf("transaction is not in the requested state")
	}

	log.Info().Msg("Sending ready event")
	readyEvt := &event.VerificationReadyEventContent{
		FromDevice: vh.client.DeviceID,
		Methods:    vh.supportedMethods,
	}
	err := vh.sendVerificationEvent(ctx, txn, event.InRoomVerificationReady, readyEvt)
	if err != nil {
		return err
	}
	txn.VerificationState = verificationStateReady

	if slices.Contains(txn.TheirSupportedMethods, event.VerificationMethodQRCodeShow) {
		vh.scanQRCode(ctx, txn.TransactionID)
	}

	return vh.generateAndShowQRCode(ctx, txn)
}

// CancelVerification cancels a verification request. The transaction ID should
// be the transaction ID of a verification request that was received via the
// VerificationRequested callback in [RequiredCallbacks].
func (vh *VerificationHelper) CancelVerification(ctx context.Context, txnID id.VerificationTransactionID, code event.VerificationCancelCode, reason string) error {
	log := vh.getLog(ctx).With().
		Str("verification_action", "cancel verification").
		Stringer("transaction_id", txnID).
		Logger()
	ctx = log.WithContext(ctx)

	txn, ok := vh.activeTransactions[txnID]
	if !ok {
		return fmt.Errorf("unknown transaction ID")
	}
	return vh.cancelVerificationTxn(ctx, txn, code, reason)
}

// sendVerificationEvent sends a verification event to the other user's device
// setting the m.relates_to or transaction ID as necessary.
//
// Notes:
//
//   - "content" must implement [event.Relatable] and
//     [event.VerificationTransactionable].
//   - evtType can be either the to-device or in-room version of the event type
//     as it is always stringified.
func (vh *VerificationHelper) sendVerificationEvent(ctx context.Context, txn *verificationTransaction, evtType event.Type, content any) error {
	if txn.RoomID != "" {
		content.(event.Relatable).SetRelatesTo(&event.RelatesTo{Type: event.RelReference, EventID: id.EventID(txn.TransactionID)})
		_, err := vh.client.SendMessageEvent(ctx, txn.RoomID, evtType, &event.Content{
			Parsed: content,
		})
		if err != nil {
			return fmt.Errorf("failed to send start event: %w", err)
		}
	} else {
		content.(event.VerificationTransactionable).SetTransactionID(txn.TransactionID)
		req := mautrix.ReqSendToDevice{Messages: map[id.UserID]map[id.DeviceID]*event.Content{
			txn.TheirUser: {
				txn.TheirDevice: &event.Content{Parsed: content},
			},
		}}
		_, err := vh.client.SendToDevice(ctx, evtType, &req)
		if err != nil {
			return fmt.Errorf("failed to send start event: %w", err)
		}
	}
	return nil
}

func (vh *VerificationHelper) cancelVerificationTxn(ctx context.Context, txn *verificationTransaction, code event.VerificationCancelCode, reasonFmtStr string, fmtArgs ...any) error {
	log := vh.getLog(ctx)
	reason := fmt.Sprintf(reasonFmtStr, fmtArgs...)
	log.Info().
		Stringer("transaction_id", txn.TransactionID).
		Str("code", string(code)).
		Str("reason", reason).
		Msg("Sending cancellation event")
	cancelEvt := &event.VerificationCancelEventContent{
		Code:   code,
		Reason: reason,
	}
	err := vh.sendVerificationEvent(ctx, txn, event.InRoomVerificationCancel, cancelEvt)
	if err != nil {
		return err
	}
	txn.VerificationState = verificationStateCancelled
	vh.verificationCancelledCallback(ctx, txn.TransactionID, code, reason)
	return nil
}

func (vh *VerificationHelper) onVerificationRequest(ctx context.Context, evt *event.Event) {
	logCtx := vh.getLog(ctx).With().
		Str("verification_action", "verification request").
		Stringer("sender", evt.Sender)
	if evt.RoomID != "" {
		logCtx = logCtx.
			Stringer("room_id", evt.RoomID).
			Stringer("event_id", evt.ID)
	}
	log := logCtx.Logger()

	var verificationRequest *event.VerificationRequestEventContent
	switch evt.Type {
	case event.EventMessage:
		to := evt.Content.AsMessage().To
		if to != vh.client.UserID {
			log.Info().Stringer("to", to).Msg("Ignoring verification request for another user")
			return
		}

		verificationRequest = event.VerificationRequestEventContentFromMessage(evt)
	case event.ToDeviceVerificationRequest:
		verificationRequest = evt.Content.AsVerificationRequest()
	default:
		log.Warn().Str("type", evt.Type.Type).Msg("Ignoring verification request of unknown type")
		return
	}

	if verificationRequest.FromDevice == vh.client.DeviceID {
		log.Warn().Msg("Ignoring verification request from our own device. Why did it even get sent to us?")
		return
	}

	if verificationRequest.TransactionID == "" {
		log.Warn().Msg("Ignoring verification request without a transaction ID")
		return
	}

	log = log.With().Any("requested_methods", verificationRequest.Methods).Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("Received verification request")

	vh.activeTransactionsLock.Lock()
	_, ok := vh.activeTransactions[verificationRequest.TransactionID]
	if ok {
		vh.activeTransactionsLock.Unlock()
		log.Info().Msg("Ignoring verification request for an already active transaction")
		return
	}
	vh.activeTransactions[verificationRequest.TransactionID] = &verificationTransaction{
		RoomID:                evt.RoomID,
		VerificationState:     verificationStateRequested,
		TransactionID:         verificationRequest.TransactionID,
		TheirDevice:           verificationRequest.FromDevice,
		TheirUser:             evt.Sender,
		TheirSupportedMethods: verificationRequest.Methods,
	}
	vh.activeTransactionsLock.Unlock()

	vh.verificationRequested(ctx, verificationRequest.TransactionID, evt.Sender)
}

func (vh *VerificationHelper) onVerificationReady(ctx context.Context, txn *verificationTransaction, evt *event.Event) {
	log := vh.getLog(ctx).With().
		Str("verification_action", "verification ready").
		Logger()

	if txn.VerificationState != verificationStateRequested {
		log.Warn().Msg("Ignoring verification ready event for a transaction that is not in the requested state")
		return
	}

	vh.activeTransactionsLock.Lock()
	defer vh.activeTransactionsLock.Unlock()

	readyEvt := evt.Content.AsVerificationReady()

	// Update the transaction state.
	txn.VerificationState = verificationStateReady
	txn.TheirDevice = readyEvt.FromDevice
	txn.TheirSupportedMethods = readyEvt.Methods

	// If we sent this verification request, send cancellations to all of the
	// other devices.
	if len(txn.SentToDeviceIDs) > 0 {
		content := &event.Content{
			Parsed: &event.VerificationCancelEventContent{
				ToDeviceVerificationEvent: event.ToDeviceVerificationEvent{TransactionID: txn.TransactionID},
				Code:                      event.VerificationCancelCodeAccepted,
				Reason:                    "The verification was accepted on another device.",
			},
		}
		devices, err := vh.mach.CryptoStore.GetDevices(ctx, txn.TheirUser)
		if err != nil {
			vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUser, "failed to get devices for %s: %v", txn.TheirUser, err)
			return
		}
		req := mautrix.ReqSendToDevice{Messages: map[id.UserID]map[id.DeviceID]*event.Content{txn.TheirUser: {}}}
		for deviceID := range devices {
			if deviceID == txn.TheirDevice {
				// Don't ever send a cancellation to the device that accepted
				// the request.
				continue
			}

			req.Messages[txn.TheirUser][deviceID] = content
		}
		_, err = vh.client.SendToDevice(ctx, event.ToDeviceVerificationRequest, &req)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to send cancellation requests")
		}
	}

	if slices.Contains(txn.TheirSupportedMethods, event.VerificationMethodQRCodeShow) {
		vh.scanQRCode(ctx, txn.TransactionID)
	}

	err := vh.generateAndShowQRCode(ctx, txn)
	if err != nil {
		vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUser, "failed to generate and show QR code: %v", err)
	}
}

func (vh *VerificationHelper) onVerificationStart(ctx context.Context, txn *verificationTransaction, evt *event.Event) {
	startEvt := evt.Content.AsVerificationStart()
	log := vh.getLog(ctx).With().
		Str("verification_action", "verification start").
		Str("method", string(startEvt.Method)).
		Logger()
	ctx = log.WithContext(ctx)

	vh.activeTransactionsLock.Lock()
	defer vh.activeTransactionsLock.Unlock()

	if txn.VerificationState == verificationStateSASStarted || txn.VerificationState == verificationStateOurQRScanned || txn.VerificationState == verificationStateTheirQRScanned {
		// We might have sent the event, and they also sent an event.
		if txn.StartEventContent == nil || !txn.StartedByUs {
			// We didn't sent a start event yet, so we have gotten ourselves
			// into a bad state. They've either sent two start events, or we
			// have gone on to a new state.
			vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUnexpectedMessage,
				"got repeat start event from other user")
			return
		}

		// Otherwise, we need to implement the following algorithm from Section
		// 11.12.2.1 of the Spec:
		// https://spec.matrix.org/v1.9/client-server-api/#key-verification-framework
		//
		// If Alice's and Bob's clients both send an m.key.verification.start
		// message, and both specify the same verification method, then the
		// m.key.verification.start message sent by the user whose ID is the
		// lexicographically largest user ID should be ignored, and the
		// situation should be treated the same as if only the user with the
		// lexicographically smallest user ID had sent the
		// m.key.verification.start message. In the case where the user IDs are
		// the same (that is, when a user is verifying their own device), then
		// the device IDs should be compared instead. If the two
		// m.key.verification.start messages do not specify the same
		// verification method, then the verification should be cancelled with
		// a code of m.unexpected_message.

		if txn.StartEventContent.Method != startEvt.Method {
			vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUnexpectedMessage, "the start events have different verification methods")
			return
		}

		if txn.TheirUser < vh.client.UserID || (txn.TheirUser == vh.client.UserID && txn.TheirDevice < vh.client.DeviceID) {
			// Use their start event instead of ours
			txn.StartedByUs = false
			txn.StartEventContent = startEvt
		}
	} else if txn.VerificationState != verificationStateReady {
		vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUnexpectedMessage,
			"got start event for transaction that is not in ready state")
		return
	}

	switch startEvt.Method {
	case event.VerificationMethodSAS:
		txn.VerificationState = verificationStateSASStarted
		if err := vh.onVerificationStartSAS(ctx, txn, evt); err != nil {
			vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUser, "failed to handle SAS verification start: %v", err)
		}
	case event.VerificationMethodReciprocate:
		log.Info().Msg("Received reciprocate start event")
		if !bytes.Equal(txn.QRCodeSharedSecret, startEvt.Secret) {
			vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeKeyMismatch, "reciprocated shared secret does not match")
			return
		}
		txn.VerificationState = verificationStateOurQRScanned
		vh.qrCodeScaned(ctx, txn.TransactionID)
	default:
		// Note that we should never get m.qr_code.show.v1 or m.qr_code.scan.v1
		// here, since the start command for scanning and showing QR codes
		// should be of type m.reciprocate.v1.
		log.Error().Str("method", string(startEvt.Method)).Msg("Unsupported verification method in start event")
		vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUnknownMethod, fmt.Sprintf("unknown method %s", startEvt.Method))
	}
}

func (vh *VerificationHelper) onVerificationDone(ctx context.Context, txn *verificationTransaction, evt *event.Event) {
	vh.getLog(ctx).Info().
		Str("verification_action", "done").
		Stringer("transaction_id", txn.TransactionID).
		Msg("Verification done")
	vh.activeTransactionsLock.Lock()
	defer vh.activeTransactionsLock.Unlock()

	if txn.VerificationState != verificationStateTheirQRScanned && txn.VerificationState != verificationStateSASMACExchanged {
		vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUnexpectedMessage,
			"got done event for transaction that is not in QR-scanned or MAC-exchanged state")
		return
	}

	txn.VerificationState = verificationStateDone
	txn.ReceivedTheirDone = true
	if txn.SentOurDone {
		vh.verificationDone(ctx, txn.TransactionID)
	}
}

func (vh *VerificationHelper) onVerificationCancel(ctx context.Context, txn *verificationTransaction, evt *event.Event) {
	cancelEvt := evt.Content.AsVerificationCancel()
	vh.getLog(ctx).Info().
		Str("verification_action", "cancel").
		Stringer("transaction_id", txn.TransactionID).
		Str("cancel_code", string(cancelEvt.Code)).
		Str("reason", cancelEvt.Reason).
		Msg("Verification was cancelled")
	vh.activeTransactionsLock.Lock()
	defer vh.activeTransactionsLock.Unlock()
	txn.VerificationState = verificationStateCancelled
	vh.verificationCancelledCallback(ctx, txn.TransactionID, cancelEvt.Code, cancelEvt.Reason)
}
