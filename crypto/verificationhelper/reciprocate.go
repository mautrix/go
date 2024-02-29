// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package verificationhelper

import (
	"bytes"
	"context"
	"fmt"

	"golang.org/x/exp/slices"

	"github.com/element-hq/mautrix-go/event"
	"github.com/element-hq/mautrix-go/id"
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

	txn, ok := vh.activeTransactions[qrCode.TransactionID]
	if !ok {
		log.Warn().Msg("Ignoring QR code scan for an unknown transaction")
		return nil
	} else if txn.VerificationState != verificationStateReady {
		log.Warn().Msg("Ignoring QR code scan for a transaction that is not in the ready state")
		return nil
	}
	txn.VerificationState = verificationStateTheirQRScanned

	// Verify the keys
	log.Info().Msg("Verifying keys from QR code")

	switch qrCode.Mode {
	case QRCodeModeCrossSigning:
		panic("unimplemented")
		// TODO verify and sign their master key
	case QRCodeModeSelfVerifyingMasterKeyTrusted:
		// The QR was created by a device that trusts the master key, which
		// means that we don't trust the key. Key1 is the master key public
		// key, and Key2 is what the other device thinks our device key is.

		if vh.client.UserID != txn.TheirUser {
			return fmt.Errorf("mode %d is only allowed when the other user is the same as the current user", qrCode.Mode)
		}

		// Verify the master key is correct
		crossSigningPubkeys := vh.mach.GetOwnCrossSigningPublicKeys(ctx)
		if bytes.Equal(crossSigningPubkeys.MasterKey.Bytes(), qrCode.Key1[:]) {
			log.Info().Msg("Verified that the other device has the same master key")
		} else {
			return fmt.Errorf("the master key does not match")
		}

		// Verify that the device key that the other device things we have is
		// correct.
		myKeys := vh.mach.OwnIdentity()
		if bytes.Equal(myKeys.SigningKey.Bytes(), qrCode.Key2[:]) {
			log.Info().Msg("Verified that the other device has the correct key for this device")
		} else {
			return fmt.Errorf("the other device has the wrong key for this device")
		}

	case QRCodeModeSelfVerifyingMasterKeyUntrusted:
		// The QR was created by a device that does not trust the master key,
		// which means that we do trust the master key. Key1 is the other
		// device's device key, and Key2 is what the other device thinks the
		// master key is.

		if vh.client.UserID != txn.TheirUser {
			return fmt.Errorf("mode %d is only allowed when the other user is the same as the current user", qrCode.Mode)
		}

		// Get their device
		theirDevice, err := vh.mach.GetOrFetchDevice(ctx, txn.TheirUser, txn.TheirDevice)
		if err != nil {
			return err
		}

		// Verify that the other device's key is what we expect.
		if bytes.Equal(theirDevice.SigningKey.Bytes(), qrCode.Key1[:]) {
			log.Info().Msg("Verified that the other device key is what we expected")
		} else {
			return fmt.Errorf("the other device's key is not what we expected")
		}

		// Verify that what they think the master key is is correct.
		if bytes.Equal(vh.mach.GetOwnCrossSigningPublicKeys(ctx).MasterKey.Bytes(), qrCode.Key2[:]) {
			log.Info().Msg("Verified that the other device has the correct master key")
		} else {
			return fmt.Errorf("the master key does not match")
		}

		// Trust their device
		theirDevice.Trust = id.TrustStateVerified
		err = vh.mach.CryptoStore.PutDevice(ctx, txn.TheirUser, theirDevice)
		if err != nil {
			return fmt.Errorf("failed to update device trust state after verifying: %w", err)
		}

		// Cross-sign their device with the self-signing key
		err = vh.mach.SignOwnDevice(ctx, theirDevice)
		if err != nil {
			return fmt.Errorf("failed to sign their device: %w", err)
		}
	default:
		return fmt.Errorf("unknown QR code mode %d", qrCode.Mode)
	}

	// Send a m.key.verification.start event with the secret
	txn.StartEventContent = &event.VerificationStartEventContent{
		FromDevice: vh.client.DeviceID,
		Method:     event.VerificationMethodReciprocate,
		Secret:     qrCode.SharedSecret,
	}
	err = vh.sendVerificationEvent(ctx, txn, event.InRoomVerificationStart, txn.StartEventContent)
	if err != nil {
		return err
	}

	// Immediately send the m.key.verification.done event, as our side of the
	// transaction is done.
	return vh.sendVerificationEvent(ctx, txn, event.InRoomVerificationDone, &event.VerificationDoneEventContent{})
}

// ConfirmQRCodeScanned confirms that our QR code has been scanned and sends the
// m.key.verification.done event to the other device.
func (vh *VerificationHelper) ConfirmQRCodeScanned(ctx context.Context, txnID id.VerificationTransactionID) error {
	log := vh.getLog(ctx).With().
		Str("verification_action", "confirm QR code scanned").
		Stringer("transaction_id", txnID).
		Logger()

	vh.activeTransactionsLock.Lock()
	defer vh.activeTransactionsLock.Unlock()
	txn, ok := vh.activeTransactions[txnID]
	if !ok {
		log.Warn().Msg("Ignoring QR code scan confirmation for an unknown transaction")
		return nil
	} else if txn.VerificationState != verificationStateOurQRScanned {
		log.Warn().Msg("Ignoring QR code scan confirmation for a transaction that is not in the started state")
		return nil
	}

	log.Info().Msg("Confirming QR code scanned")

	if txn.TheirUser == vh.client.UserID {
		// Self-signing situation. Trust their device.

		// Get their device
		theirDevice, err := vh.mach.GetOrFetchDevice(ctx, txn.TheirUser, txn.TheirDevice)
		if err != nil {
			return err
		}

		// Trust their device
		theirDevice.Trust = id.TrustStateVerified
		err = vh.mach.CryptoStore.PutDevice(ctx, txn.TheirUser, theirDevice)
		if err != nil {
			return fmt.Errorf("failed to update device trust state after verifying: %w", err)
		}

		// Cross-sign their device with the self-signing key
		if vh.mach.CrossSigningKeys != nil {
			err = vh.mach.SignOwnDevice(ctx, theirDevice)
			if err != nil {
				return fmt.Errorf("failed to sign their device: %w", err)
			}
		}
	}
	// TODO: handle QR codes that are not self-signing situations

	err := vh.sendVerificationEvent(ctx, txn, event.InRoomVerificationDone, &event.VerificationDoneEventContent{})
	if err != nil {
		return err
	}

	txn.VerificationState = verificationStateDone

	// Broadcast that the verification is complete.
	vh.verificationDone(ctx, txn.TransactionID)
	return nil
}

func (vh *VerificationHelper) generateAndShowQRCode(ctx context.Context, txn *verificationTransaction) error {
	log := vh.getLog(ctx).With().
		Str("verification_action", "generate and show QR code").
		Stringer("transaction_id", txn.TransactionID).
		Logger()
	if vh.showQRCode == nil {
		log.Warn().Msg("Ignoring QR code generation request as showing a QR code is not enabled on this device")
		return nil
	}
	if !slices.Contains(txn.TheirSupportedMethods, event.VerificationMethodQRCodeScan) {
		log.Warn().Msg("Ignoring QR code generation request as other device cannot scan QR codes")
		return nil
	}

	ownCrossSigningPublicKeys := vh.mach.GetOwnCrossSigningPublicKeys(ctx)

	mode := QRCodeModeCrossSigning
	if vh.client.UserID == txn.TheirUser {
		// This is a self-signing situation.
		if trusted, err := vh.mach.IsUserTrusted(ctx, vh.client.UserID); err != nil {
			return err
		} else if trusted {
			mode = QRCodeModeSelfVerifyingMasterKeyTrusted
		} else {
			mode = QRCodeModeSelfVerifyingMasterKeyUntrusted
		}
	}

	var key1, key2 []byte
	switch mode {
	case QRCodeModeCrossSigning:
		// Key 1 is the current user's master signing key.
		key1 = ownCrossSigningPublicKeys.MasterKey.Bytes()

		// Key 2 is the other user's master signing key.
		theirSigningKeys, err := vh.mach.GetCrossSigningPublicKeys(ctx, txn.TheirUser)
		if err != nil {
			return err
		}
		key2 = theirSigningKeys.MasterKey.Bytes()
	case QRCodeModeSelfVerifyingMasterKeyTrusted:
		// Key 1 is the current user's master signing key.
		key1 = ownCrossSigningPublicKeys.MasterKey.Bytes()

		// Key 2 is the other device's key.
		theirDevice, err := vh.mach.GetOrFetchDevice(ctx, txn.TheirUser, txn.TheirDevice)
		if err != nil {
			return err
		}
		key2 = theirDevice.IdentityKey.Bytes()
	case QRCodeModeSelfVerifyingMasterKeyUntrusted:
		// Key 1 is the current device's key
		key1 = vh.mach.OwnIdentity().IdentityKey.Bytes()

		// Key 2 is the master signing key.
		key2 = ownCrossSigningPublicKeys.MasterKey.Bytes()
	default:
		log.Fatal().Str("mode", string(mode)).Msg("Unknown QR code mode")
	}

	qrCode := NewQRCode(mode, txn.TransactionID, [32]byte(key1), [32]byte(key2))
	txn.QRCodeSharedSecret = qrCode.SharedSecret
	vh.showQRCode(ctx, txn.TransactionID, qrCode)
	return nil
}
