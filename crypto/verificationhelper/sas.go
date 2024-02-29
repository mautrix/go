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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"go.mau.fi/util/jsonbytes"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/exp/slices"

	"github.com/element-hq/mautrix-go/crypto/canonicaljson"
	"github.com/element-hq/mautrix-go/event"
	"github.com/element-hq/mautrix-go/id"
)

// StartSAS starts a SAS verification flow. The transaction ID should be the
// transaction ID of a verification request that was received via the
// VerificationRequested callback in [RequiredCallbacks].
func (vh *VerificationHelper) StartSAS(ctx context.Context, txnID id.VerificationTransactionID) error {
	log := vh.getLog(ctx).With().
		Str("verification_action", "accept verification").
		Stringer("transaction_id", txnID).
		Logger()

	vh.activeTransactionsLock.Lock()
	defer vh.activeTransactionsLock.Unlock()
	txn, ok := vh.activeTransactions[txnID]
	if !ok {
		return fmt.Errorf("unknown transaction ID")
	} else if txn.VerificationState != verificationStateReady {
		return errors.New("transaction is not in ready state")
	}

	txn.VerificationState = verificationStateSASStarted
	txn.StartedByUs = true
	if !slices.Contains(txn.TheirSupportedMethods, event.VerificationMethodSAS) {
		return fmt.Errorf("the other device does not support SAS verification")
	}

	// Ensure that we have their device key.
	_, err := vh.mach.GetOrFetchDevice(ctx, txn.TheirUser, txn.TheirDevice)
	if err != nil {
		log.Err(err).Msg("Failed to fetch device")
		return err
	}

	// TODO check if the other device already has sent a start event

	log.Info().Msg("Sending start event")
	txn.StartEventContent = &event.VerificationStartEventContent{
		FromDevice: vh.client.DeviceID,
		Method:     event.VerificationMethodSAS,

		Hashes:                []event.VerificationHashMethod{event.VerificationHashMethodSHA256},
		KeyAgreementProtocols: []event.KeyAgreementProtocol{event.KeyAgreementProtocolCurve25519HKDFSHA256},
		MessageAuthenticationCodes: []event.MACMethod{
			event.MACMethodHKDFHMACSHA256,
			event.MACMethodHKDFHMACSHA256V2,
		},
		ShortAuthenticationString: []event.SASMethod{
			event.SASMethodDecimal,
			event.SASMethodEmoji,
		},
	}
	return vh.sendVerificationEvent(ctx, txn, event.InRoomVerificationStart, txn.StartEventContent)
}

// ConfirmSAS indicates that the user has confirmed that the SAS matches SAS
// shown on the other user's device.
func (vh *VerificationHelper) ConfirmSAS(ctx context.Context, txnID id.VerificationTransactionID) error {
	log := vh.getLog(ctx).With().
		Str("verification_action", "confirm SAS").
		Stringer("transaction_id", txnID).
		Logger()

	vh.activeTransactionsLock.Lock()
	defer vh.activeTransactionsLock.Unlock()
	txn, ok := vh.activeTransactions[txnID]
	if !ok {
		return fmt.Errorf("unknown transaction ID")
	}

	var err error
	keys := map[id.KeyID]jsonbytes.UnpaddedBytes{}

	log.Info().Msg("Signing keys")

	// TODO actually sign some keys
	// My device key
	myDevice := vh.mach.OwnIdentity()
	myDeviceKeyID := id.NewKeyID(id.KeyAlgorithmEd25519, myDevice.DeviceID.String())
	keys[myDeviceKeyID], err = vh.verificationMACHKDF(txn, vh.client.UserID, vh.client.DeviceID, txn.TheirUser, txn.TheirDevice, myDeviceKeyID.String(), myDevice.IdentityKey.String())
	if err != nil {
		return err
	}

	// Master signing key
	// TODO how to detect whether or not we trust the master key?

	var keyIDs []string
	for keyID := range keys {
		keyIDs = append(keyIDs, keyID.String())
	}
	slices.Sort(keyIDs)
	keysMAC, err := vh.verificationMACHKDF(txn, vh.client.UserID, vh.client.DeviceID, txn.TheirUser, txn.TheirDevice, "KEY_IDS", strings.Join(keyIDs, ","))
	if err != nil {
		return err
	}

	macEventContent := &event.VerificationMacEventContent{
		Keys: keysMAC,
		MAC:  keys,
	}
	return vh.sendVerificationEvent(ctx, txn, event.InRoomVerificationMAC, macEventContent)
}

// onVerificationStartSAS handles the m.key.verification.start events with
// method of m.sas.v1 by implementing steps 4-7 of [Section 11.12.2.2] of the
// Spec.
//
// [Section 11.12.2.2]: https://spec.matrix.org/v1.9/client-server-api/#short-authentication-string-sas-verification
func (vh *VerificationHelper) onVerificationStartSAS(ctx context.Context, txn *verificationTransaction, evt *event.Event) error {
	if txn.VerificationState != verificationStateReady {
		vh.unexpectedEvent(ctx, txn)
		return nil // return nil since we already sent a cancellation event in vh.unexpectedEvent
	}

	startEvt := evt.Content.AsVerificationStart()
	log := vh.getLog(ctx)
	log.Info().Msg("Received SAS verification start event")

	_, err := vh.mach.GetOrFetchDevice(ctx, evt.Sender, startEvt.FromDevice)
	if err != nil {
		log.Err(err).Msg("Failed to fetch device")
		return err
	}

	keyAggreementProtocol := event.KeyAgreementProtocolCurve25519HKDFSHA256
	if !startEvt.SupportsKeyAgreementProtocol(keyAggreementProtocol) {
		return fmt.Errorf("the other device does not support any key agreement protocols that we support")
	}

	hashAlgorithm := event.VerificationHashMethodSHA256
	if !startEvt.SupportsHashMethod(hashAlgorithm) {
		return fmt.Errorf("the other device does not support any hash algorithms that we support")
	}

	macMethod := event.MACMethodHKDFHMACSHA256V2
	if !startEvt.SupportsMACMethod(macMethod) {
		if startEvt.SupportsMACMethod(event.MACMethodHKDFHMACSHA256) {
			macMethod = event.MACMethodHKDFHMACSHA256
		} else {
			return fmt.Errorf("the other device does not support any message authentication codes that we support")
		}
	}

	var sasMethods []event.SASMethod
	for _, sasMethod := range startEvt.ShortAuthenticationString {
		if sasMethod == event.SASMethodDecimal || sasMethod == event.SASMethodEmoji {
			sasMethods = append(sasMethods, sasMethod)
		}
	}
	if len(sasMethods) == 0 {
		return fmt.Errorf("the other device does not support any short authentication string methods that we support")
	}

	ephemeralKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	txn.MACMethod = macMethod
	txn.EphemeralKey = ephemeralKey
	txn.StartEventContent = startEvt

	commitment, err := calculateCommitment(ephemeralKey.PublicKey(), startEvt)
	if err != nil {
		return fmt.Errorf("failed to calculate commitment: %w", err)
	}

	err = vh.sendVerificationEvent(ctx, txn, event.InRoomVerificationAccept, &event.VerificationAcceptEventContent{
		Commitment:                commitment,
		Hash:                      hashAlgorithm,
		KeyAgreementProtocol:      keyAggreementProtocol,
		MessageAuthenticationCode: macMethod,
		ShortAuthenticationString: sasMethods,
	})
	if err != nil {
		return fmt.Errorf("failed to send accept event: %w", err)
	}
	txn.VerificationState = verificationStateSASAccepted
	return nil
}

func calculateCommitment(ephemeralPubKey *ecdh.PublicKey, startEvt *event.VerificationStartEventContent) ([]byte, error) {
	// The commitmentHashInput is the hash (encoded as unpadded base64) of the
	// concatenation of the device's ephemeral public key (encoded as
	// unpadded base64) and the canonical JSON representation of the
	// m.key.verification.start message.
	//
	// I have no idea why they chose to base64-encode the public key before
	// hashing it, but we are just stuck on that.
	commitmentHashInput := sha256.New()
	commitmentHashInput.Write([]byte(base64.RawStdEncoding.EncodeToString(ephemeralPubKey.Bytes())))
	encodedStartEvt, err := json.Marshal(startEvt)
	if err != nil {
		return nil, err
	}
	commitmentHashInput.Write(canonicaljson.CanonicalJSONAssumeValid(encodedStartEvt))
	return commitmentHashInput.Sum(nil), nil
}

// onVerificationAccept handles the m.key.verification.accept SAS verification
// event. This follows Step 4 of [Section 11.12.2.2] of the Spec.
//
// [Section 11.12.2.2]: https://spec.matrix.org/v1.9/client-server-api/#short-authentication-string-sas-verification
func (vh *VerificationHelper) onVerificationAccept(ctx context.Context, txn *verificationTransaction, evt *event.Event) {
	acceptEvt := evt.Content.AsVerificationAccept()
	log := vh.getLog(ctx).With().
		Str("verification_action", "accept").
		Stringer("transaction_id", txn.TransactionID).
		Str("commitment", base64.RawStdEncoding.EncodeToString(acceptEvt.Commitment)).
		Str("hash", string(acceptEvt.Hash)).
		Str("key_agreement_protocol", string(acceptEvt.KeyAgreementProtocol)).
		Str("message_authentication_code", string(acceptEvt.MessageAuthenticationCode)).
		Any("short_authentication_string", acceptEvt.ShortAuthenticationString).
		Logger()
	log.Info().Msg("Received SAS verification accept event")

	vh.activeTransactionsLock.Lock()
	defer vh.activeTransactionsLock.Unlock()
	if txn.VerificationState != verificationStateSASStarted {
		vh.unexpectedEvent(ctx, txn)
		return
	}

	ephemeralKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		log.Err(err).Msg("Failed to generate ephemeral key")
		return
	}

	err = vh.sendVerificationEvent(ctx, txn, event.InRoomVerificationKey, &event.VerificationKeyEventContent{
		Key: ephemeralKey.PublicKey().Bytes(),
	})
	if err != nil {
		log.Err(err).Msg("Failed to send key event")
		return
	}

	txn.VerificationState = verificationStateSASAccepted
	txn.MACMethod = acceptEvt.MessageAuthenticationCode
	txn.Commitment = acceptEvt.Commitment
	txn.EphemeralKey = ephemeralKey
	txn.EphemeralPublicKeyShared = true
}

func (vh *VerificationHelper) onVerificationKey(ctx context.Context, txn *verificationTransaction, evt *event.Event) {
	log := vh.getLog(ctx).With().
		Str("verification_action", "key").
		Logger()
	keyEvt := evt.Content.AsVerificationKey()
	vh.activeTransactionsLock.Lock()
	defer vh.activeTransactionsLock.Unlock()

	if txn.VerificationState != verificationStateSASAccepted {
		vh.unexpectedEvent(ctx, txn)
		return
	}

	var err error
	txn.OtherPublicKey, err = ecdh.X25519().NewPublicKey(keyEvt.Key)
	if err != nil {
		log.Err(err).Msg("Failed to generate other public key")
		return
	}

	if txn.EphemeralPublicKeyShared {
		// Verify that the commitment hash is correct
		commitment, err := calculateCommitment(txn.OtherPublicKey, txn.StartEventContent)
		if err != nil {
			log.Err(err).Msg("Failed to calculate commitment")
			return
		}
		if !bytes.Equal(commitment, txn.Commitment) {
			err := vh.sendVerificationEvent(ctx, txn, event.InRoomVerificationCancel, &event.VerificationCancelEventContent{
				Code:   event.VerificationCancelCodeKeyMismatch,
				Reason: "The key was not the one we expected.",
			})
			if err != nil {
				log.Err(err).Msg("Failed to send cancellation event")
			}
			return
		}
	} else {
		err = vh.sendVerificationEvent(ctx, txn, event.InRoomVerificationKey, &event.VerificationKeyEventContent{
			Key: txn.EphemeralKey.PublicKey().Bytes(),
		})
		if err != nil {
			log.Err(err).Msg("Failed to send key event")
			return
		}
		txn.EphemeralPublicKeyShared = true
	}
	txn.VerificationState = verificationStateSASKeysExchanged

	sasBytes, err := vh.verificationSASHKDF(txn)
	if err != nil {
		log.Err(err).Msg("Failed to compute HKDF for SAS")
		return
	}

	var decimals []int
	var emojis []rune
	if txn.StartEventContent.SupportsSASMethod(event.SASMethodDecimal) {
		decimals = []int{
			(int(sasBytes[0])<<5 | int(sasBytes[1])>>3) + 1000,
			((int(sasBytes[1])&0x07)<<10 | int(sasBytes[2])<<2 | int(sasBytes[3])>>6) + 1000,
			((int(sasBytes[3])&0x3f)<<7 | int(sasBytes[4])>>1) + 1000,
		}
	}
	if txn.StartEventContent.SupportsSASMethod(event.SASMethodEmoji) {
		sasNum := uint64(sasBytes[0])<<40 | uint64(sasBytes[1])<<32 | uint64(sasBytes[2])<<24 |
			uint64(sasBytes[3])<<16 | uint64(sasBytes[4])<<8 | uint64(sasBytes[5])

		for i := 0; i < 7; i++ {
			// Right shift the number and then mask the lowest 6 bits.
			emojiIdx := (sasNum >> uint(48-(i+1)*6)) & 0b111111
			emojis = append(emojis, allEmojis[emojiIdx])
		}
	}
	vh.showSAS(ctx, txn.TransactionID, emojis, decimals)
}

func (vh *VerificationHelper) verificationSASHKDF(txn *verificationTransaction) ([]byte, error) {
	sharedSecret, err := txn.EphemeralKey.ECDH(txn.OtherPublicKey)
	if err != nil {
		return nil, err
	}

	// Perform the SAS HKDF calculation according to Section 11.12.2.2.4 of the
	// Spec:
	// https://spec.matrix.org/v1.9/client-server-api/#sas-hkdf-calculation
	myInfo := strings.Join([]string{
		vh.client.UserID.String(),
		vh.client.DeviceID.String(),
		base64.RawStdEncoding.EncodeToString(txn.EphemeralKey.PublicKey().Bytes()),
	}, "|")

	theirInfo := strings.Join([]string{
		txn.TheirUser.String(),
		txn.TheirDevice.String(),
		base64.RawStdEncoding.EncodeToString(txn.OtherPublicKey.Bytes()),
	}, "|")

	var infoBuf bytes.Buffer
	infoBuf.WriteString("MATRIX_KEY_VERIFICATION_SAS|")
	if txn.StartedByUs {
		infoBuf.WriteString(myInfo + "|" + theirInfo)
	} else {
		infoBuf.WriteString(theirInfo + "|" + myInfo)
	}
	infoBuf.WriteRune('|')
	infoBuf.WriteString(txn.TransactionID.String())

	reader := hkdf.New(sha256.New, sharedSecret, nil, infoBuf.Bytes())
	output := make([]byte, 6)
	_, err = reader.Read(output)
	return output, err
}

// BrokenB64Encode implements the incorrect base64 serialization in libolm for
// the hkdf-hmac-sha256 MAC method. The bug is caused by the input and output
// buffers being equal to one another during the base64 encoding.
//
// This function is narrowly scoped to this specific bug, and does not work
// generally (it only supports if the input is 32-bytes).
//
// See https://github.com/matrix-org/matrix-spec-proposals/pull/3783 and
// https://gitlab.matrix.org/matrix-org/olm/-/merge_requests/16 for details.
//
// Deprecated: never use this. It is only here for compatibility with the
// broken libolm implementation.
func BrokenB64Encode(input []byte) string {
	encodeBase64 := []byte{
		0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
		0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
		0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
		0x59, 0x5A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
		0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
		0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
		0x77, 0x78, 0x79, 0x7A, 0x30, 0x31, 0x32, 0x33,
		0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x2B, 0x2F,
	}

	output := make([]byte, 43)
	copy(output, input)

	pos := 0
	outputPos := 0
	for pos != 30 {
		value := int32(output[pos])
		value <<= 8
		value |= int32(output[pos+1])
		value <<= 8
		value |= int32(output[pos+2])
		pos += 3
		output[outputPos] = encodeBase64[(value>>18)&0x3F]
		output[outputPos+1] = encodeBase64[(value>>12)&0x3F]
		output[outputPos+2] = encodeBase64[(value>>6)&0x3F]
		output[outputPos+3] = encodeBase64[value&0x3F]
		outputPos += 4
	}
	// This is the mangling that libolm does to the base64 encoding.
	value := int32(output[pos])
	value <<= 8
	value |= int32(output[pos+1])
	value <<= 2
	output[outputPos] = encodeBase64[(value>>12)&0x3F]
	output[outputPos+1] = encodeBase64[(value>>6)&0x3F]
	output[outputPos+2] = encodeBase64[value&0x3F]
	return string(output)
}

func (vh *VerificationHelper) verificationMACHKDF(txn *verificationTransaction, senderUser id.UserID, senderDevice id.DeviceID, receivingUser id.UserID, receivingDevice id.DeviceID, keyID, key string) ([]byte, error) {
	sharedSecret, err := txn.EphemeralKey.ECDH(txn.OtherPublicKey)
	if err != nil {
		return nil, err
	}
	fmt.Printf("KEYID %s\n", keyID)
	fmt.Printf("KEY   %s\n", key)

	var infoBuf bytes.Buffer
	infoBuf.WriteString("MATRIX_KEY_VERIFICATION_MAC")
	infoBuf.WriteString(senderUser.String())
	infoBuf.WriteString(senderDevice.String())
	infoBuf.WriteString(receivingUser.String())
	infoBuf.WriteString(receivingDevice.String())
	infoBuf.WriteString(txn.TransactionID.String())
	infoBuf.WriteString(keyID)

	reader := hkdf.New(sha256.New, sharedSecret, nil, infoBuf.Bytes())
	macKey := make([]byte, 32)
	_, err = reader.Read(macKey)
	if err != nil {
		return nil, err
	}

	hash := hmac.New(sha256.New, macKey)
	hash.Write([]byte(key))
	sum := hash.Sum(nil)
	if txn.MACMethod == event.MACMethodHKDFHMACSHA256 {
		fmt.Printf("MANGLING %v\n", sum)
		fmt.Printf("%s\n", BrokenB64Encode(sum))
		sum, err = base64.RawStdEncoding.DecodeString(BrokenB64Encode(sum))
		if err != nil {
			panic(err)
		}
		fmt.Printf("MANGLING %v\n", sum)
	}
	return sum, nil
}

var allEmojis = []rune{
	'🐶',
	'🐱',
	'🦁',
	'🐎',
	'🦄',
	'🐷',
	'🐘',
	'🐰',
	'🐼',
	'🐓',
	'🐧',
	'🐢',
	'🐟',
	'🐙',
	'🦋',
	'🌷',
	'🌳',
	'🌵',
	'🍄',
	'🌏',
	'🌙',
	'☁',
	'🔥',
	'🍌',
	'🍎',
	'🍓',
	'🌽',
	'🍕',
	'🎂',
	'❤',
	'😀',
	'🤖',
	'🎩',
	'👓',
	'🔧',
	'🎅',
	'👍',
	'☂',
	'⌛',
	'⏰',
	'🎁',
	'💡',
	'📕',
	'✏',
	'📎',
	'✂',
	'🔒',
	'🔑',
	'🔨',
	'☎',
	'🏁',
	'🚂',
	'🚲',
	'✈',
	'🚀',
	'🏆',
	'⚽',
	'🎸',
	'🎺',
	'🔔',
	'⚓',
	'🎧',
	'📁',
	'📌',
}

func (vh *VerificationHelper) onVerificationMAC(ctx context.Context, txn *verificationTransaction, evt *event.Event) {
	log := vh.getLog(ctx).With().
		Str("verification_action", "mac").
		Logger()
	log.Info().Msg("Received SAS verification MAC event")
	macEvt := evt.Content.AsVerificationMAC()
	jsonBytes, _ := json.Marshal(macEvt)
	fmt.Printf("%s\n", jsonBytes)
	var keyIDs []string
	// for keyID, mac := range macEvt.MAC {
	// 	log.Info().Str("key_id", keyID.String()).Msg("Received MAC for key")
	// 	keyIDs = append(keyIDs, keyID.String())

	// 	var key string

	// 	expectedMAC, err := vh.verificationMACHKDF(txn, txn.TheirUser, txn.TheirDevice, vh.client.UserID, vh.client.DeviceID, keyID.String(), key)
	// 	if err != nil {
	// 		vh.verificationError(ctx, txn.TransactionID, fmt.Errorf("failed to calculate key MAC: %w", err))
	// 		return
	// 	}
	// 	if !bytes.Equal(expectedMAC, mac) {
	// 		vh.verificationError(ctx, txn.TransactionID, fmt.Errorf("MAC mismatch for key %s", keyID))
	// 		return
	// 	}
	// }

	log.Info().Msg("Verifying MAC for all sent keys")
	expectedKeyMAC, err := vh.verificationMACHKDF(txn, txn.TheirUser, txn.TheirDevice, vh.client.UserID, vh.client.DeviceID, "KEY_IDS", strings.Join(keyIDs, ","))
	if err != nil {
		vh.verificationError(ctx, txn.TransactionID, fmt.Errorf("failed to calculate key list MAC: %w", err))
		return
	}
	fmt.Printf("%d %v\n", len(expectedKeyMAC), expectedKeyMAC)
	fmt.Printf("%d %v\n", len(macEvt.Keys), macEvt.Keys)
	if !bytes.Equal(expectedKeyMAC, macEvt.Keys) {
		vh.verificationError(ctx, txn.TransactionID, fmt.Errorf("key list MAC mismatch"))
		return
	}

	// TODO actually do a trust thing
}
