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

	"golang.org/x/exp/slices"

	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// HandleScannedQRData verifies the keys from a scanned QR code and if
// successful, sends the m.key.verification.start event and
// m.key.verification.done event.
func (vh *VerificationHelper) HandleScannedQRData(ctx context.Context, data []byte) error {
	qrCode, err := NewQRCodeFromBytes(data)
	if err != nil {
		return err
	}
	log := vh.getLog(ctx).With().
		Str("verification_action", "handle scanned QR data").
		Stringer("transaction_id", qrCode.TransactionID).
		Int("mode", int(qrCode.Mode)).
		Logger()
	ctx = log.WithContext(ctx)

	vh.activeTransactionsLock.Lock()
	defer vh.activeTransactionsLock.Unlock()

	txn, err := vh.store.GetVerificationTransaction(ctx, qrCode.TransactionID)
	if err != nil {
		return fmt.Errorf("failed to get transaction %s: %w", qrCode.TransactionID, err)
	} else if txn.VerificationState != VerificationStateReady {
		return vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUnexpectedMessage, "transaction found in the QR code is not in the ready state")
	}
	txn.VerificationState = VerificationStateTheirQRScanned

	// Verify the keys
	log.Info().Msg("Verifying keys from QR code")

	ownCrossSigningPublicKeys := vh.mach.GetOwnCrossSigningPublicKeys(ctx)
	if ownCrossSigningPublicKeys == nil {
		return crypto.ErrCrossSigningPubkeysNotCached
	}

	switch qrCode.Mode {
	case QRCodeModeCrossSigning:
		theirSigningKeys, err := vh.mach.GetCrossSigningPublicKeys(ctx, txn.TheirUserID)
		if err != nil {
			return vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeKeyMismatch, "couldn't get %s's cross-signing keys: %w", txn.TheirUserID, err)
		}
		if bytes.Equal(theirSigningKeys.MasterKey.Bytes(), qrCode.Key1[:]) {
			log.Info().Msg("Verified that the other device has the master key we expected")
		} else {
			return vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeKeyMismatch, "the other device does not have the master key we expected")
		}

		// Verify the master key is correct
		if bytes.Equal(ownCrossSigningPublicKeys.MasterKey.Bytes(), qrCode.Key2[:]) {
			log.Info().Msg("Verified that the other device has the same master key")
		} else {
			return vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeKeyMismatch, "the master key does not match")
		}

		if err := vh.mach.SignUser(ctx, txn.TheirUserID, theirSigningKeys.MasterKey); err != nil {
			return vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeInternalError, "failed to sign their master key: %w", err)
		}
	case QRCodeModeSelfVerifyingMasterKeyTrusted:
		// The QR was created by a device that trusts the master key, which
		// means that we don't trust the key. Key1 is the master key public
		// key, and Key2 is what the other device thinks our device key is.

		if vh.client.UserID != txn.TheirUserID {
			return vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUnexpectedMessage, "mode %d is only allowed when the other user is the same as the current user", qrCode.Mode)
		}

		// Verify the master key is correct
		if bytes.Equal(ownCrossSigningPublicKeys.MasterKey.Bytes(), qrCode.Key1[:]) {
			log.Info().Msg("Verified that the other device has the same master key")
		} else {
			return vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeKeyMismatch, "the master key does not match")
		}

		// Verify that the device key that the other device things we have is
		// correct.
		myKeys := vh.mach.OwnIdentity()
		if bytes.Equal(myKeys.SigningKey.Bytes(), qrCode.Key2[:]) {
			log.Info().Msg("Verified that the other device has the correct key for this device")
		} else {
			return vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeKeyMismatch, "the other device has the wrong key for this device")
		}

		if err := vh.mach.SignOwnMasterKey(ctx); err != nil {
			return vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeInternalError, "failed to sign own master key: %w", err)
		}
	case QRCodeModeSelfVerifyingMasterKeyUntrusted:
		// The QR was created by a device that does not trust the master key,
		// which means that we do trust the master key. Key1 is the other
		// device's device key, and Key2 is what the other device thinks the
		// master key is.

		// Check that we actually trust the master key.
		if trusted, err := vh.mach.CryptoStore.IsKeySignedBy(ctx, vh.client.UserID, ownCrossSigningPublicKeys.MasterKey, vh.client.UserID, vh.mach.OwnIdentity().SigningKey); err != nil {
			return err
		} else if !trusted {
			return vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeMasterKeyNotTrusted, "the master key is not trusted by this device, cannot verify device that does not trust the master key")
		}

		if vh.client.UserID != txn.TheirUserID {
			return vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUnexpectedMessage, "mode %d is only allowed when the other user is the same as the current user", qrCode.Mode)
		}

		// Get their device
		theirDevice, err := vh.mach.GetOrFetchDevice(ctx, txn.TheirUserID, txn.TheirDeviceID)
		if err != nil {
			return vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeInternalError, "failed to get their device: %w", err)
		}

		// Verify that the other device's key is what we expect.
		if bytes.Equal(theirDevice.SigningKey.Bytes(), qrCode.Key1[:]) {
			log.Info().Msg("Verified that the other device key is what we expected")
		} else {
			return vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeKeyMismatch, "the other device's key is not what we expected")
		}

		// Verify that what they think the master key is is correct.
		if bytes.Equal(ownCrossSigningPublicKeys.MasterKey.Bytes(), qrCode.Key2[:]) {
			log.Info().Msg("Verified that the other device has the correct master key")
		} else {
			return vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeKeyMismatch, "the master key does not match")
		}

		// Trust their device
		theirDevice.Trust = id.TrustStateVerified
		err = vh.mach.CryptoStore.PutDevice(ctx, txn.TheirUserID, theirDevice)
		if err != nil {
			return vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeInternalError, "failed to update device trust state after verifying: %+v", err)
		}

		// Cross-sign their device with the self-signing key
		err = vh.mach.SignOwnDevice(ctx, theirDevice)
		if err != nil {
			return vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeInternalError, "failed to sign their device: %+v", err)
		}
	default:
		return vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUnexpectedMessage, "unknown QR code mode %d", qrCode.Mode)
	}

	// Send a m.key.verification.start event with the secret
	txn.StartedByUs = true
	txn.StartEventContent = &event.VerificationStartEventContent{
		FromDevice: vh.client.DeviceID,
		Method:     event.VerificationMethodReciprocate,
		Secret:     qrCode.SharedSecret,
	}
	err = vh.sendVerificationEvent(ctx, txn, event.InRoomVerificationStart, txn.StartEventContent)
	if err != nil {
		return fmt.Errorf("failed to send m.key.verification.start event: %w", err)
	}
	log.Debug().Msg("Successfully sent the m.key.verification.start event")

	// Immediately send the m.key.verification.done event, as our side of the
	// transaction is done.
	err = vh.sendVerificationEvent(ctx, txn, event.InRoomVerificationDone, &event.VerificationDoneEventContent{})
	if err != nil {
		return fmt.Errorf("failed to send m.key.verification.done event: %w", err)
	}
	log.Debug().Msg("Successfully sent the m.key.verification.done event")
	txn.SentOurDone = true
	if txn.ReceivedTheirDone {
		log.Debug().Msg("We already received their done event. Setting verification state to done.")
		if err = vh.store.DeleteVerification(ctx, txn.TransactionID); err != nil {
			return err
		}
		vh.verificationDone(ctx, txn.TransactionID, txn.StartEventContent.Method)
	} else {
		return vh.store.SaveVerificationTransaction(ctx, txn)
	}
	return nil
}

// ConfirmQRCodeScanned confirms that our QR code has been scanned and sends
// the m.key.verification.done event to the other device for the given
// transaction ID. The transaction ID should be one received via the
// VerificationRequested callback in [RequiredCallbacks] or the
// [StartVerification] or [StartInRoomVerification] functions.
func (vh *VerificationHelper) ConfirmQRCodeScanned(ctx context.Context, txnID id.VerificationTransactionID) error {
	log := vh.getLog(ctx).With().
		Str("verification_action", "confirm QR code scanned").
		Stringer("transaction_id", txnID).
		Logger()
	ctx = log.WithContext(ctx)

	vh.activeTransactionsLock.Lock()
	defer vh.activeTransactionsLock.Unlock()
	txn, err := vh.store.GetVerificationTransaction(ctx, txnID)
	if err != nil {
		return fmt.Errorf("failed to get transaction %s: %w", txnID, err)
	} else if txn.VerificationState != VerificationStateOurQRScanned {
		return fmt.Errorf("transaction is not in the scanned state")
	}

	log.Info().Msg("Confirming QR code scanned")

	// Get their device
	theirDevice, err := vh.mach.GetOrFetchDevice(ctx, txn.TheirUserID, txn.TheirDeviceID)
	if err != nil {
		return err
	}

	// Trust their device
	theirDevice.Trust = id.TrustStateVerified
	err = vh.mach.CryptoStore.PutDevice(ctx, txn.TheirUserID, theirDevice)
	if err != nil {
		return fmt.Errorf("failed to update device trust state after verifying: %w", err)
	}

	if txn.TheirUserID == vh.client.UserID {
		// Self-signing situation.
		//
		// If we have the cross-signing keys, then we need to sign their device
		// using the self-signing key. Otherwise, they have the master private
		// key, so we need to trust the master public key.
		if vh.mach.CrossSigningKeys != nil {
			err = vh.mach.SignOwnDevice(ctx, theirDevice)
			if err != nil {
				return fmt.Errorf("failed to sign our own new device: %w", err)
			}
		} else {
			err = vh.mach.SignOwnMasterKey(ctx)
			if err != nil {
				return fmt.Errorf("failed to sign our own master key: %w", err)
			}
		}
	} else {
		// Cross-signing situation. Sign their master key.
		theirSigningKeys, err := vh.mach.GetCrossSigningPublicKeys(ctx, txn.TheirUserID)
		if err != nil {
			return vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeKeyMismatch, "couldn't get %s's cross-signing keys: %w", txn.TheirUserID, err)
		}

		if err := vh.mach.SignUser(ctx, txn.TheirUserID, theirSigningKeys.MasterKey); err != nil {
			return vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeInternalError, "failed to sign their master key: %w", err)
		}
	}

	err = vh.sendVerificationEvent(ctx, txn, event.InRoomVerificationDone, &event.VerificationDoneEventContent{})
	if err != nil {
		return err
	}
	txn.SentOurDone = true
	if txn.ReceivedTheirDone {
		if err = vh.store.DeleteVerification(ctx, txn.TransactionID); err != nil {
			return err
		}
		vh.verificationDone(ctx, txn.TransactionID, txn.StartEventContent.Method)
	} else {
		return vh.store.SaveVerificationTransaction(ctx, txn)
	}
	return nil
}

func (vh *VerificationHelper) generateQRCode(ctx context.Context, txn *VerificationTransaction) (*QRCode, error) {
	log := vh.getLog(ctx).With().
		Str("verification_action", "generate and show QR code").
		Stringer("transaction_id", txn.TransactionID).
		Logger()
	ctx = log.WithContext(ctx)

	if !slices.Contains(vh.supportedMethods, event.VerificationMethodReciprocate) ||
		!slices.Contains(txn.TheirSupportedMethods, event.VerificationMethodReciprocate) {
		log.Info().Msg("Ignoring QR code generation request as reciprocating is not supported by both devices")
		return nil, nil
	} else if !slices.Contains(txn.TheirSupportedMethods, event.VerificationMethodQRCodeScan) {
		log.Info().Msg("Ignoring QR code generation request as other device cannot scan QR codes")
		return nil, nil
	}

	ownCrossSigningPublicKeys := vh.mach.GetOwnCrossSigningPublicKeys(ctx)
	if ownCrossSigningPublicKeys == nil || len(ownCrossSigningPublicKeys.MasterKey) == 0 {
		return nil, errors.New("failed to get own cross-signing master public key")
	}

	ownMasterKeyTrusted, err := vh.mach.CryptoStore.IsKeySignedBy(ctx, vh.client.UserID, ownCrossSigningPublicKeys.MasterKey, vh.client.UserID, vh.mach.OwnIdentity().SigningKey)
	if err != nil {
		return nil, err
	}
	mode := QRCodeModeCrossSigning
	if vh.client.UserID == txn.TheirUserID {
		// This is a self-signing situation.
		if ownMasterKeyTrusted {
			mode = QRCodeModeSelfVerifyingMasterKeyTrusted
		} else {
			mode = QRCodeModeSelfVerifyingMasterKeyUntrusted
		}
	} else {
		// This is a cross-signing situation.
		if !ownMasterKeyTrusted {
			return nil, errors.New("cannot cross-sign other device when own master key is not trusted")
		}
		mode = QRCodeModeCrossSigning
	}

	var key1, key2 []byte
	switch mode {
	case QRCodeModeCrossSigning:
		// Key 1 is the current user's master signing key.
		key1 = ownCrossSigningPublicKeys.MasterKey.Bytes()

		// Key 2 is the other user's master signing key.
		theirSigningKeys, err := vh.mach.GetCrossSigningPublicKeys(ctx, txn.TheirUserID)
		if err != nil {
			return nil, err
		}
		key2 = theirSigningKeys.MasterKey.Bytes()
	case QRCodeModeSelfVerifyingMasterKeyTrusted:
		// Key 1 is the current user's master signing key.
		key1 = ownCrossSigningPublicKeys.MasterKey.Bytes()

		// Key 2 is the other device's key.
		theirDevice, err := vh.mach.GetOrFetchDevice(ctx, txn.TheirUserID, txn.TheirDeviceID)
		if err != nil {
			return nil, err
		}
		key2 = theirDevice.SigningKey.Bytes()
	case QRCodeModeSelfVerifyingMasterKeyUntrusted:
		// Key 1 is the current device's key
		key1 = vh.mach.OwnIdentity().SigningKey.Bytes()

		// Key 2 is the master signing key.
		key2 = ownCrossSigningPublicKeys.MasterKey.Bytes()
	default:
		log.Fatal().Int("mode", int(mode)).Msg("Unknown QR code mode")
	}

	qrCode := NewQRCode(mode, txn.TransactionID, [32]byte(key1), [32]byte(key2))
	txn.QRCodeSharedSecret = qrCode.SharedSecret
	return qrCode, nil
}
