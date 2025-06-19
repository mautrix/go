// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package verificationhelper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exslices"
	"go.mau.fi/util/jsontime"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// RequiredCallbacks is an interface representing the callbacks required for
// the [VerificationHelper].
type RequiredCallbacks interface {
	// VerificationRequested is called when a verification request is received
	// from another device.
	VerificationRequested(ctx context.Context, txnID id.VerificationTransactionID, from id.UserID, fromDevice id.DeviceID)

	// VerificationReady is called when a verification request has been
	// accepted by both parties.
	VerificationReady(ctx context.Context, txnID id.VerificationTransactionID, otherDeviceID id.DeviceID, supportsSAS, supportsScanQRCode bool, qrCode *QRCode)

	// VerificationCancelled is called when the verification is cancelled.
	VerificationCancelled(ctx context.Context, txnID id.VerificationTransactionID, code event.VerificationCancelCode, reason string)

	// VerificationDone is called when the verification is done.
	VerificationDone(ctx context.Context, txnID id.VerificationTransactionID, method event.VerificationMethod)
}

type ShowSASCallbacks interface {
	// ShowSAS is a callback that is called when the SAS verification has
	// generated a short authentication string to show. It is guaranteed that
	// either the emojis and emoji descriptions lists, or the decimals list, or
	// both will be present.
	ShowSAS(ctx context.Context, txnID id.VerificationTransactionID, emojis []rune, emojiDescriptions []string, decimals []int)
}

type ShowQRCodeCallbacks interface {
	// QRCodeScanned is called when the other user has scanned the QR code and
	// sent the m.key.verification.start event.
	QRCodeScanned(ctx context.Context, txnID id.VerificationTransactionID)
}

type VerificationHelper struct {
	client *mautrix.Client
	mach   *crypto.OlmMachine

	store                  VerificationStore
	activeTransactionsLock sync.Mutex

	// supportedMethods are the methods that *we* support
	supportedMethods              []event.VerificationMethod
	verificationRequested         func(ctx context.Context, txnID id.VerificationTransactionID, from id.UserID, fromDevice id.DeviceID)
	verificationReady             func(ctx context.Context, txnID id.VerificationTransactionID, otherDeviceID id.DeviceID, supportsSAS, supportsScanQRCode bool, qrCode *QRCode)
	verificationCancelledCallback func(ctx context.Context, txnID id.VerificationTransactionID, code event.VerificationCancelCode, reason string)
	verificationDone              func(ctx context.Context, txnID id.VerificationTransactionID, method event.VerificationMethod)

	// showSAS is a callback that will be called after the SAS verification
	// dance is complete and we want the client to show the emojis/decimals
	showSAS func(ctx context.Context, txnID id.VerificationTransactionID, emojis []rune, emojiDescriptions []string, decimals []int)
	// qrCodeScanned is a callback that will be called when the other device
	// scanned the QR code we are showing
	qrCodeScanned func(ctx context.Context, txnID id.VerificationTransactionID)
}

var _ mautrix.VerificationHelper = (*VerificationHelper)(nil)

func NewVerificationHelper(client *mautrix.Client, mach *crypto.OlmMachine, store VerificationStore, callbacks any, supportsQRShow, supportsQRScan, supportsSAS bool) *VerificationHelper {
	if client.Crypto == nil {
		panic("client.Crypto is nil")
	}

	if store == nil {
		store = NewInMemoryVerificationStore()
	}

	helper := VerificationHelper{
		client: client,
		mach:   mach,
		store:  store,
	}

	if c, ok := callbacks.(RequiredCallbacks); !ok {
		panic("callbacks must implement RequiredCallbacks")
	} else {
		helper.verificationRequested = c.VerificationRequested
		helper.verificationReady = c.VerificationReady
		helper.verificationCancelledCallback = c.VerificationCancelled
		helper.verificationDone = c.VerificationDone
	}

	if supportsSAS {
		if c, ok := callbacks.(ShowSASCallbacks); !ok {
			panic("callbacks must implement showSAS if supportsSAS is true")
		} else {
			helper.supportedMethods = append(helper.supportedMethods, event.VerificationMethodSAS)
			helper.showSAS = c.ShowSAS
		}
	}
	if supportsQRShow {
		if c, ok := callbacks.(ShowQRCodeCallbacks); !ok {
			panic("callbacks must implement ShowQRCodeCallbacks if supportsQRShow is true")
		} else {
			helper.supportedMethods = append(helper.supportedMethods, event.VerificationMethodQRCodeShow)
			helper.supportedMethods = append(helper.supportedMethods, event.VerificationMethodReciprocate)
			helper.qrCodeScanned = c.QRCodeScanned
		}
	}
	if supportsQRScan {
		helper.supportedMethods = append(helper.supportedMethods, event.VerificationMethodQRCodeScan)
		helper.supportedMethods = append(helper.supportedMethods, event.VerificationMethodReciprocate)
	}
	helper.supportedMethods = exslices.DeduplicateUnsorted(helper.supportedMethods)
	return &helper
}

func (vh *VerificationHelper) getLog(ctx context.Context) *zerolog.Logger {
	logger := zerolog.Ctx(ctx).With().
		Str("component", "verification").
		Stringer("device_id", vh.client.DeviceID).
		Stringer("user_id", vh.client.UserID).
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
	wrapHandler := func(callback func(context.Context, VerificationTransaction, *event.Event)) func(context.Context, *event.Event) {
		return func(ctx context.Context, evt *event.Event) {
			log := vh.getLog(ctx).With().
				Str("verification_action", "check transaction ID").
				Stringer("sender", evt.Sender).
				Stringer("room_id", evt.RoomID).
				Stringer("event_id", evt.ID).
				Stringer("event_type", evt.Type).
				Logger()
			ctx = log.WithContext(ctx)

			var transactionID id.VerificationTransactionID
			if evt.ID != "" {
				transactionID = id.VerificationTransactionID(evt.ID)
			} else {
				if txnID, ok := evt.Content.Parsed.(event.VerificationTransactionable); !ok {
					log.Warn().Msg("Ignoring verification event without a transaction ID")
					return
				} else {
					transactionID = txnID.GetTransactionID()
				}
			}
			log = log.With().Stringer("transaction_id", transactionID).Logger()

			vh.activeTransactionsLock.Lock()
			txn, err := vh.store.GetVerificationTransaction(ctx, transactionID)
			if err != nil && errors.Is(err, ErrUnknownVerificationTransaction) {
				log.Err(err).Msg("failed to get verification transaction")
				vh.activeTransactionsLock.Unlock()
				return
			} else if errors.Is(err, ErrUnknownVerificationTransaction) {
				// If it's a cancellation event for an unknown transaction, we
				// can just ignore it.
				if evt.Type == event.ToDeviceVerificationCancel || evt.Type == event.InRoomVerificationCancel {
					log.Info().Msg("Ignoring verification cancellation event for an unknown transaction")
					vh.activeTransactionsLock.Unlock()
					return
				}

				log.Warn().Msg("Sending cancellation event for unknown transaction ID")

				// We have to create a fake transaction so that the call to
				// cancelVerificationTxn works.
				txn = VerificationTransaction{
					ExpirationTime: jsontime.UnixMilli{Time: time.Now().Add(time.Minute * 10)},
					RoomID:         evt.RoomID,
					TheirUserID:    evt.Sender,
				}
				if transactionable, ok := evt.Content.Parsed.(event.VerificationTransactionable); ok {
					txn.TransactionID = transactionable.GetTransactionID()
				} else {
					txn.TransactionID = id.VerificationTransactionID(evt.ID)
				}
				if fromDevice, ok := evt.Content.Raw["from_device"]; ok {
					txn.TheirDeviceID = id.DeviceID(fromDevice.(string))
				}

				// Send a cancellation event.
				vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUnknownTransaction, "The transaction ID was not recognized.")
				vh.activeTransactionsLock.Unlock()
				return
			} else {
				vh.activeTransactionsLock.Unlock()
			}

			logCtx := log.With().
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

	allTransactions, err := vh.store.GetAllVerificationTransactions(ctx)
	for _, txn := range allTransactions {
		vh.expireTransactionAt(txn.TransactionID, txn.ExpirationTime.Time)
	}
	return err
}

// StartVerification starts an interactive verification flow with the given
// user via a to-device event.
func (vh *VerificationHelper) StartVerification(ctx context.Context, to id.UserID) (id.VerificationTransactionID, error) {
	if len(vh.supportedMethods) == 0 {
		return "", fmt.Errorf("no supported verification methods")
	}

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

	log := vh.getLog(ctx).With().
		Str("verification_action", "start verification").
		Stringer("transaction_id", txnID).
		Stringer("to", to).
		Any("device_ids", maps.Keys(devices)).
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("Sending verification request")

	now := time.Now()
	content := &event.Content{
		Parsed: &event.VerificationRequestEventContent{
			ToDeviceVerificationEvent: event.ToDeviceVerificationEvent{TransactionID: txnID},
			FromDevice:                vh.client.DeviceID,
			Methods:                   vh.supportedMethods,
			Timestamp:                 jsontime.UM(now),
		},
	}
	vh.expireTransactionAt(txnID, now.Add(time.Minute*10))

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
	return txnID, vh.store.SaveVerificationTransaction(ctx, VerificationTransaction{
		ExpirationTime:    jsontime.UnixMilli{Time: time.Now().Add(time.Minute * 10)},
		VerificationState: VerificationStateRequested,
		TransactionID:     txnID,
		TheirUserID:       to,
		SentToDeviceIDs:   maps.Keys(devices),
	})
}

// StartInRoomVerification starts an interactive verification flow with the
// given user in the given room.
func (vh *VerificationHelper) StartInRoomVerification(ctx context.Context, roomID id.RoomID, to id.UserID) (id.VerificationTransactionID, error) {
	log := vh.getLog(ctx).With().
		Str("verification_action", "start in-room verification").
		Stringer("room_id", roomID).
		Stringer("to", to).
		Logger()
	ctx = log.WithContext(ctx)

	log.Info().Msg("Sending verification request")
	content := event.MessageEventContent{
		MsgType:    event.MsgVerificationRequest,
		Body:       fmt.Sprintf("%s is requesting to verify your device, but your client does not support verification, so you may need to use a different verification method.", vh.client.UserID),
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
	return txnID, vh.store.SaveVerificationTransaction(ctx, VerificationTransaction{
		ExpirationTime:    jsontime.UnixMilli{Time: time.Now().Add(time.Minute * 10)},
		RoomID:            roomID,
		VerificationState: VerificationStateRequested,
		TransactionID:     txnID,
		TheirUserID:       to,
	})
}

// AcceptVerification accepts a verification request. The transaction ID should
// be the transaction ID of a verification request that was received via the
// VerificationRequested callback in [RequiredCallbacks].
func (vh *VerificationHelper) AcceptVerification(ctx context.Context, txnID id.VerificationTransactionID) error {
	vh.activeTransactionsLock.Lock()
	defer vh.activeTransactionsLock.Unlock()

	log := vh.getLog(ctx).With().
		Str("verification_action", "accept verification").
		Stringer("transaction_id", txnID).
		Logger()
	ctx = log.WithContext(ctx)

	txn, err := vh.store.GetVerificationTransaction(ctx, txnID)
	if err != nil {
		return err
	} else if txn.VerificationState != VerificationStateRequested {
		return fmt.Errorf("transaction is not in the requested state")
	}

	supportedMethods := map[event.VerificationMethod]struct{}{}
	for _, method := range txn.TheirSupportedMethods {
		switch method {
		case event.VerificationMethodSAS:
			if slices.Contains(vh.supportedMethods, event.VerificationMethodSAS) {
				supportedMethods[event.VerificationMethodSAS] = struct{}{}
			}
		case event.VerificationMethodQRCodeShow:
			if slices.Contains(vh.supportedMethods, event.VerificationMethodQRCodeScan) {
				supportedMethods[event.VerificationMethodQRCodeScan] = struct{}{}
				supportedMethods[event.VerificationMethodReciprocate] = struct{}{}
			}
		case event.VerificationMethodQRCodeScan:
			if slices.Contains(vh.supportedMethods, event.VerificationMethodQRCodeShow) {
				supportedMethods[event.VerificationMethodQRCodeShow] = struct{}{}
				supportedMethods[event.VerificationMethodReciprocate] = struct{}{}
			}
		}
	}

	log.Info().Any("methods", maps.Keys(supportedMethods)).Msg("Sending ready event")
	readyEvt := &event.VerificationReadyEventContent{
		FromDevice: vh.client.DeviceID,
		Methods:    maps.Keys(supportedMethods),
	}
	err = vh.sendVerificationEvent(ctx, txn, event.InRoomVerificationReady, readyEvt)
	if err != nil {
		return err
	}
	txn.VerificationState = VerificationStateReady

	supportsSAS := slices.Contains(vh.supportedMethods, event.VerificationMethodSAS) &&
		slices.Contains(txn.TheirSupportedMethods, event.VerificationMethodSAS)
	supportsReciprocate := slices.Contains(vh.supportedMethods, event.VerificationMethodReciprocate) &&
		slices.Contains(txn.TheirSupportedMethods, event.VerificationMethodReciprocate)
	supportsScanQRCode := supportsReciprocate &&
		slices.Contains(vh.supportedMethods, event.VerificationMethodQRCodeScan) &&
		slices.Contains(txn.TheirSupportedMethods, event.VerificationMethodQRCodeShow)

	qrCode, err := vh.generateQRCode(ctx, &txn)
	if err != nil {
		return err
	}
	vh.verificationReady(ctx, txn.TransactionID, txn.TheirDeviceID, supportsSAS, supportsScanQRCode, qrCode)
	return vh.store.SaveVerificationTransaction(ctx, txn)
}

// DismissVerification dismisses the verification request with the given
// transaction ID. The transaction ID should be one received via the
// VerificationRequested callback in [RequiredCallbacks] or the
// [StartVerification] or [StartInRoomVerification] functions.
func (vh *VerificationHelper) DismissVerification(ctx context.Context, txnID id.VerificationTransactionID) error {
	vh.activeTransactionsLock.Lock()
	defer vh.activeTransactionsLock.Unlock()
	return vh.store.DeleteVerification(ctx, txnID)
}

// DismissVerification cancels the verification request with the given
// transaction ID. The transaction ID should be one received via the
// VerificationRequested callback in [RequiredCallbacks] or the
// [StartVerification] or [StartInRoomVerification] functions.
func (vh *VerificationHelper) CancelVerification(ctx context.Context, txnID id.VerificationTransactionID, code event.VerificationCancelCode, reason string) error {
	vh.activeTransactionsLock.Lock()
	defer vh.activeTransactionsLock.Unlock()

	txn, err := vh.store.GetVerificationTransaction(ctx, txnID)
	if err != nil {
		return err
	}
	log := vh.getLog(ctx).With().
		Str("verification_action", "cancel verification").
		Stringer("transaction_id", txnID).
		Str("code", string(code)).
		Str("reason", reason).
		Logger()
	ctx = log.WithContext(ctx)

	log.Info().Msg("Sending cancellation event")
	cancelEvt := &event.VerificationCancelEventContent{Code: code, Reason: reason}
	if len(txn.RoomID) > 0 {
		// Sending the cancellation event to the room.
		err := vh.sendVerificationEvent(ctx, txn, event.InRoomVerificationCancel, cancelEvt)
		if err != nil {
			return fmt.Errorf("failed to send cancel verification event (code: %s, reason: %s): %w", code, reason, err)
		}
	} else {
		cancelEvt.SetTransactionID(txn.TransactionID)
		req := mautrix.ReqSendToDevice{Messages: map[id.UserID]map[id.DeviceID]*event.Content{
			txn.TheirUserID: {},
		}}
		if len(txn.TheirDeviceID) > 0 {
			// Send the cancellation event to only the device that accepted the
			// verification request. All of the other devices already received a
			// cancellation event with code "m.acceped".
			req.Messages[txn.TheirUserID][txn.TheirDeviceID] = &event.Content{Parsed: cancelEvt}
		} else {
			// Send the cancellation event to all of the devices that we sent the
			// request to.
			for _, deviceID := range txn.SentToDeviceIDs {
				if deviceID != vh.client.DeviceID {
					req.Messages[txn.TheirUserID][deviceID] = &event.Content{Parsed: cancelEvt}
				}
			}
		}
		_, err := vh.client.SendToDevice(ctx, event.ToDeviceVerificationCancel, &req)
		if err != nil {
			return fmt.Errorf("failed to send m.key.verification.cancel event to %v: %w", maps.Keys(req.Messages[txn.TheirUserID]), err)
		}
	}
	return vh.store.DeleteVerification(ctx, txn.TransactionID)
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
func (vh *VerificationHelper) sendVerificationEvent(ctx context.Context, txn VerificationTransaction, evtType event.Type, content any) error {
	if txn.RoomID != "" {
		content.(event.Relatable).SetRelatesTo(&event.RelatesTo{Type: event.RelReference, EventID: id.EventID(txn.TransactionID)})
		_, err := vh.client.SendMessageEvent(ctx, txn.RoomID, evtType, &event.Content{
			Parsed: content,
		})
		if err != nil {
			return fmt.Errorf("failed to send %s event to %s: %w", evtType.String(), txn.RoomID, err)
		}
	} else {
		content.(event.VerificationTransactionable).SetTransactionID(txn.TransactionID)
		req := mautrix.ReqSendToDevice{Messages: map[id.UserID]map[id.DeviceID]*event.Content{
			txn.TheirUserID: {
				txn.TheirDeviceID: &event.Content{Parsed: content},
			},
		}}
		_, err := vh.client.SendToDevice(ctx, evtType, &req)
		if err != nil {
			return fmt.Errorf("failed to send %s event to %s: %w", evtType.String(), txn.TheirDeviceID, err)
		}
	}
	return nil
}

// cancelVerificationTxn cancels a verification transaction with the given code
// and reason. It always returns an error, which is the formatted error message
// (this is allows the caller to return the result of this function call
// directly to expose the error to its caller).
//
// Must always be called with the activeTransactionsLock held.
func (vh *VerificationHelper) cancelVerificationTxn(ctx context.Context, txn VerificationTransaction, code event.VerificationCancelCode, reasonFmtStr string, fmtArgs ...any) error {
	reason := fmt.Errorf(reasonFmtStr, fmtArgs...).Error()
	log := vh.getLog(ctx).With().
		Stringer("transaction_id", txn.TransactionID).
		Str("code", string(code)).
		Str("reason", reason).
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("Sending cancellation event")
	cancelEvt := &event.VerificationCancelEventContent{Code: code, Reason: reason}
	err := vh.sendVerificationEvent(ctx, txn, event.InRoomVerificationCancel, cancelEvt)
	if err != nil {
		log.Err(err).Msg("failed to send cancellation event")
		return fmt.Errorf("failed to send cancel verification event (code: %s, reason: %s): %w", code, reason, err)
	}
	if err = vh.store.DeleteVerification(ctx, txn.TransactionID); err != nil {
		log.Err(err).Msg("deleting verification failed")
	}
	vh.verificationCancelledCallback(ctx, txn.TransactionID, code, reason)
	return fmt.Errorf("verification cancelled (code: %s): %s", code, reason)
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

	if verificationRequest.Timestamp.Add(10 * time.Minute).Before(time.Now()) {
		log.Warn().Msg("Ignoring verification request that is over ten minutes old")
		return
	}

	if len(verificationRequest.TransactionID) == 0 {
		log.Warn().Msg("Ignoring verification request without a transaction ID")
		return
	}

	log = log.With().
		Any("requested_methods", verificationRequest.Methods).
		Stringer("transaction_id", verificationRequest.TransactionID).
		Stringer("from_device", verificationRequest.FromDevice).
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("Received verification request")

	// Check if we support any of the methods listed
	var supportsAnyMethod bool
	for _, method := range verificationRequest.Methods {
		switch method {
		case event.VerificationMethodSAS:
			supportsAnyMethod = slices.Contains(vh.supportedMethods, event.VerificationMethodSAS)
		case event.VerificationMethodQRCodeScan:
			supportsAnyMethod = slices.Contains(vh.supportedMethods, event.VerificationMethodQRCodeShow) &&
				slices.Contains(verificationRequest.Methods, event.VerificationMethodReciprocate)
		case event.VerificationMethodQRCodeShow:
			supportsAnyMethod = slices.Contains(vh.supportedMethods, event.VerificationMethodQRCodeScan) &&
				slices.Contains(verificationRequest.Methods, event.VerificationMethodReciprocate)
		}
		if supportsAnyMethod {
			break
		}
	}
	if !supportsAnyMethod {
		log.Warn().Msg("Ignoring verification request that doesn't have any methods we support")
		return
	}

	vh.activeTransactionsLock.Lock()
	newTxn := VerificationTransaction{
		ExpirationTime:        jsontime.UnixMilli{Time: verificationRequest.Timestamp.Add(time.Minute * 10)},
		RoomID:                evt.RoomID,
		VerificationState:     VerificationStateRequested,
		TransactionID:         verificationRequest.TransactionID,
		TheirDeviceID:         verificationRequest.FromDevice,
		TheirUserID:           evt.Sender,
		TheirSupportedMethods: verificationRequest.Methods,
	}
	if txn, err := vh.store.FindVerificationTransactionForUserDevice(ctx, evt.Sender, verificationRequest.FromDevice); err != nil && !errors.Is(err, ErrUnknownVerificationTransaction) {
		log.Err(err).Stringer("sender", evt.Sender).Stringer("device_id", verificationRequest.FromDevice).Msg("failed to find verification transaction")
		vh.activeTransactionsLock.Unlock()
		return
	} else if !errors.Is(err, ErrUnknownVerificationTransaction) {
		if txn.TransactionID == verificationRequest.TransactionID {
			vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUnexpectedMessage, "received a new verification request for the same transaction ID")
		} else {
			vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUnexpectedMessage, "received multiple verification requests from the same device")
			vh.cancelVerificationTxn(ctx, newTxn, event.VerificationCancelCodeUnexpectedMessage, "received multiple verification requests from the same device")
		}
		vh.activeTransactionsLock.Unlock()
		return
	}
	if err := vh.store.SaveVerificationTransaction(ctx, newTxn); err != nil {
		log.Err(err).Msg("failed to save verification transaction")
	}
	vh.activeTransactionsLock.Unlock()

	vh.expireTransactionAt(verificationRequest.TransactionID, verificationRequest.Timestamp.Add(time.Minute*10))
	vh.verificationRequested(ctx, verificationRequest.TransactionID, evt.Sender, verificationRequest.FromDevice)
}

func (vh *VerificationHelper) expireTransactionAt(txnID id.VerificationTransactionID, expiresAt time.Time) {
	go func() {
		time.Sleep(time.Until(expiresAt))

		vh.activeTransactionsLock.Lock()
		defer vh.activeTransactionsLock.Unlock()

		txn, err := vh.store.GetVerificationTransaction(context.Background(), txnID)
		if err == ErrUnknownVerificationTransaction {
			// Already deleted, nothing to expire
			return
		} else if err != nil {
			vh.getLog(context.Background()).Err(err).Msg("failed to get verification transaction to expire")
		} else {
			vh.cancelVerificationTxn(context.Background(), txn, event.VerificationCancelCodeTimeout, "verification timed out")
		}
	}()
}

func (vh *VerificationHelper) onVerificationReady(ctx context.Context, txn VerificationTransaction, evt *event.Event) {
	log := vh.getLog(ctx).With().
		Str("verification_action", "verification ready").
		Logger()
	ctx = log.WithContext(ctx)

	vh.activeTransactionsLock.Lock()
	defer vh.activeTransactionsLock.Unlock()

	if txn.VerificationState != VerificationStateRequested {
		vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUnexpectedMessage, "verification ready event received for a transaction that is not in the requested state")
		return
	}

	readyEvt := evt.Content.AsVerificationReady()

	// Update the transaction state.
	txn.VerificationState = VerificationStateReady
	txn.TheirDeviceID = readyEvt.FromDevice
	txn.TheirSupportedMethods = readyEvt.Methods

	log.Info().
		Stringer("their_device_id", txn.TheirDeviceID).
		Any("their_supported_methods", txn.TheirSupportedMethods).
		Msg("Received verification ready event")

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
		req := mautrix.ReqSendToDevice{Messages: map[id.UserID]map[id.DeviceID]*event.Content{txn.TheirUserID: {}}}
		for _, deviceID := range txn.SentToDeviceIDs {
			if deviceID == txn.TheirDeviceID || deviceID == vh.client.DeviceID {
				// Don't ever send a cancellation to the device that accepted
				// the request or to our own device (which can happen if this
				// is a self-verification).
				continue
			}

			req.Messages[txn.TheirUserID][deviceID] = content
		}
		_, err := vh.client.SendToDevice(ctx, event.ToDeviceVerificationCancel, &req)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to send cancellation requests")
		}
	}

	supportsSAS := slices.Contains(vh.supportedMethods, event.VerificationMethodSAS) &&
		slices.Contains(txn.TheirSupportedMethods, event.VerificationMethodSAS)
	supportsReciprocate := slices.Contains(vh.supportedMethods, event.VerificationMethodReciprocate) &&
		slices.Contains(txn.TheirSupportedMethods, event.VerificationMethodReciprocate)
	supportsScanQRCode := supportsReciprocate &&
		slices.Contains(vh.supportedMethods, event.VerificationMethodQRCodeScan) &&
		slices.Contains(txn.TheirSupportedMethods, event.VerificationMethodQRCodeShow)

	qrCode, err := vh.generateQRCode(ctx, &txn)
	if err != nil {
		vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeInternalError, "failed to generate QR code: %w", err)
		return
	}

	vh.verificationReady(ctx, txn.TransactionID, txn.TheirDeviceID, supportsSAS, supportsScanQRCode, qrCode)

	if err := vh.store.SaveVerificationTransaction(ctx, txn); err != nil {
		vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeInternalError, "failed to save verification transaction: %w", err)
	}
}

func (vh *VerificationHelper) onVerificationStart(ctx context.Context, txn VerificationTransaction, evt *event.Event) {
	startEvt := evt.Content.AsVerificationStart()
	log := vh.getLog(ctx).With().
		Str("verification_action", "verification start").
		Str("method", string(startEvt.Method)).
		Stringer("their_device_id", txn.TheirDeviceID).
		Any("their_supported_methods", txn.TheirSupportedMethods).
		Bool("started_by_us", txn.StartedByUs).
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("Received verification start event")

	vh.activeTransactionsLock.Lock()
	defer vh.activeTransactionsLock.Unlock()

	if txn.VerificationState == VerificationStateSASStarted || txn.VerificationState == VerificationStateOurQRScanned || txn.VerificationState == VerificationStateTheirQRScanned {
		// We might have sent the event, and they also sent an event.
		if txn.StartEventContent == nil || !txn.StartedByUs {
			// We didn't sent a start event yet, so we have gotten ourselves
			// into a bad state. They've either sent two start events, or we
			// have gone on to a new state.
			vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUnexpectedMessage, "got repeat start event from other user")
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

		if txn.TheirUserID < vh.client.UserID || (txn.TheirUserID == vh.client.UserID && txn.TheirDeviceID < vh.client.DeviceID) {
			log.Debug().Msg("Using their start event instead of ours because they are alphabetically before us")
			txn.StartedByUs = false
			txn.StartEventContent = startEvt
		}
	} else if txn.VerificationState != VerificationStateReady {
		vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUnexpectedMessage, "got start event for transaction that is not in ready state")
		return
	} else {
		txn.StartEventContent = startEvt
	}

	switch startEvt.Method {
	case event.VerificationMethodSAS:
		log.Info().Msg("Received SAS start event")
		txn.VerificationState = VerificationStateSASStarted
		if err := vh.onVerificationStartSAS(ctx, txn, evt); err != nil {
			vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUser, "failed to handle SAS verification start: %w", err)
		}
	case event.VerificationMethodReciprocate:
		log.Info().Msg("Received reciprocate start event")
		if !bytes.Equal(txn.QRCodeSharedSecret, txn.StartEventContent.Secret) {
			vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeKeyMismatch, "reciprocated shared secret does not match")
			return
		}
		txn.VerificationState = VerificationStateOurQRScanned
		vh.qrCodeScanned(ctx, txn.TransactionID)
		if err := vh.store.SaveVerificationTransaction(ctx, txn); err != nil {
			log.Err(err).Msg("failed to save verification transaction")
		}
	default:
		// Note that we should never get m.qr_code.show.v1 or m.qr_code.scan.v1
		// here, since the start command for scanning and showing QR codes
		// should be of type m.reciprocate.v1.
		log.Error().Str("method", string(txn.StartEventContent.Method)).Msg("Unsupported verification method in start event")
		vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUnknownMethod, fmt.Sprintf("unknown method %s", txn.StartEventContent.Method))
	}
}

func (vh *VerificationHelper) onVerificationDone(ctx context.Context, txn VerificationTransaction, evt *event.Event) {
	log := vh.getLog(ctx).With().
		Str("verification_action", "done").
		Stringer("transaction_id", txn.TransactionID).
		Bool("sent_our_done", txn.SentOurDone).
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("Verification done")
	vh.activeTransactionsLock.Lock()
	defer vh.activeTransactionsLock.Unlock()

	if !slices.Contains([]VerificationState{
		VerificationStateTheirQRScanned, VerificationStateOurQRScanned, VerificationStateSASMACExchanged,
	}, txn.VerificationState) {
		vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUnexpectedMessage, "got done event for transaction that is not in QR-scanned or MAC-exchanged state")
		return
	}

	txn.ReceivedTheirDone = true
	if txn.SentOurDone {
		if err := vh.store.DeleteVerification(ctx, txn.TransactionID); err != nil {
			log.Err(err).Msg("Delete verification failed")
		}
		vh.verificationDone(ctx, txn.TransactionID, txn.StartEventContent.Method)
	} else if err := vh.store.SaveVerificationTransaction(ctx, txn); err != nil {
		log.Err(err).Msg("failed to save verification transaction")
	}
}

func (vh *VerificationHelper) onVerificationCancel(ctx context.Context, txn VerificationTransaction, evt *event.Event) {
	cancelEvt := evt.Content.AsVerificationCancel()
	log := vh.getLog(ctx).With().
		Str("verification_action", "cancel").
		Stringer("transaction_id", txn.TransactionID).
		Str("cancel_code", string(cancelEvt.Code)).
		Str("reason", cancelEvt.Reason).
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("Verification was cancelled")
	vh.activeTransactionsLock.Lock()
	defer vh.activeTransactionsLock.Unlock()

	// Element (and at least the old desktop client) send cancellation events
	// when the user rejects the verification request. This is really dumb,
	// because they should just instead ignore the request and not send a
	// cancellation.
	//
	// The above behavior causes a problem with the other devices that we sent
	// the verification request to because they don't know that the request was
	// cancelled.
	//
	// As a workaround, if we receive a cancellation event to a transaction
	// that is currently in the REQUESTED state, then we will send
	// cancellations to all of the devices that we sent the request to. This
	// will ensure that all of the clients know that the request was cancelled.
	if txn.VerificationState == VerificationStateRequested && len(txn.SentToDeviceIDs) > 0 {
		content := &event.Content{
			Parsed: &event.VerificationCancelEventContent{
				ToDeviceVerificationEvent: event.ToDeviceVerificationEvent{TransactionID: txn.TransactionID},
				Code:                      event.VerificationCancelCodeUser,
				Reason:                    "The verification was rejected from another device.",
			},
		}
		req := mautrix.ReqSendToDevice{Messages: map[id.UserID]map[id.DeviceID]*event.Content{txn.TheirUserID: {}}}
		for _, deviceID := range txn.SentToDeviceIDs {
			req.Messages[txn.TheirUserID][deviceID] = content
		}
		_, err := vh.client.SendToDevice(ctx, event.ToDeviceVerificationCancel, &req)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to send cancellation requests")
		}
	}

	if err := vh.store.DeleteVerification(ctx, txn.TransactionID); err != nil {
		log.Err(err).Msg("Delete verification failed")
	}
	vh.verificationCancelledCallback(ctx, txn.TransactionID, cancelEvt.Code, cancelEvt.Reason)
}
