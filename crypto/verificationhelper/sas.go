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
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"go.mau.fi/util/jsonbytes"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/exp/slices"

	"maunium.net/go/mautrix/crypto/canonicaljson"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// StartSAS starts a SAS verification flow for the given transaction ID. The
// transaction ID should be one received via the VerificationRequested callback
// in [RequiredCallbacks] or the [StartVerification] or
// [StartInRoomVerification] functions.
func (vh *VerificationHelper) StartSAS(ctx context.Context, txnID id.VerificationTransactionID) error {
	log := vh.getLog(ctx).With().
		Str("verification_action", "start SAS").
		Stringer("transaction_id", txnID).
		Logger()
	ctx = log.WithContext(ctx)

	vh.activeTransactionsLock.Lock()
	defer vh.activeTransactionsLock.Unlock()
	txn, err := vh.store.GetVerificationTransaction(ctx, txnID)
	if err != nil {
		return fmt.Errorf("failed to get verification transaction %s: %w", txnID, err)
	} else if txn.VerificationState != VerificationStateReady {
		return fmt.Errorf("transaction is not in ready state: %s", txn.VerificationState.String())
	} else if txn.StartEventContent != nil {
		return errors.New("start event already sent or received")
	}

	txn.VerificationState = VerificationStateSASStarted
	txn.StartedByUs = true
	if !slices.Contains(txn.TheirSupportedMethods, event.VerificationMethodSAS) {
		return fmt.Errorf("the other device does not support SAS verification")
	}

	// Ensure that we have their device key.
	_, err = vh.mach.GetOrFetchDevice(ctx, txn.TheirUserID, txn.TheirDeviceID)
	if err != nil {
		log.Err(err).Msg("Failed to fetch device")
		return err
	}

	log.Info().Msg("Sending start event")
	startEventContent := event.VerificationStartEventContent{
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
	if err := vh.sendVerificationEvent(ctx, txn, event.InRoomVerificationStart, &startEventContent); err != nil {
		return err
	}
	txn.StartEventContent = &startEventContent
	return vh.store.SaveVerificationTransaction(ctx, txn)
}

// ConfirmSAS indicates that the user has confirmed that the SAS matches SAS
// shown on the other user's device for the given transaction ID. The
// transaction ID should be one received via the VerificationRequested callback
// in [RequiredCallbacks] or the [StartVerification] or
// [StartInRoomVerification] functions.
func (vh *VerificationHelper) ConfirmSAS(ctx context.Context, txnID id.VerificationTransactionID) error {
	log := vh.getLog(ctx).With().
		Str("verification_action", "confirm SAS").
		Stringer("transaction_id", txnID).
		Logger()
	ctx = log.WithContext(ctx)

	vh.activeTransactionsLock.Lock()
	defer vh.activeTransactionsLock.Unlock()
	txn, err := vh.store.GetVerificationTransaction(ctx, txnID)
	if err != nil {
		return fmt.Errorf("failed to get transaction %s: %w", txnID, err)
	} else if txn.VerificationState != VerificationStateSASKeysExchanged {
		return errors.New("transaction is not in keys exchanged state")
	}

	keys := map[id.KeyID]jsonbytes.UnpaddedBytes{}

	log.Info().Msg("Signing keys")
	var masterKey string

	// My device key
	myDevice := vh.mach.OwnIdentity()
	myDeviceKeyID := id.NewKeyID(id.KeyAlgorithmEd25519, myDevice.DeviceID.String())
	keys[myDeviceKeyID], err = vh.verificationMACHKDF(txn, vh.client.UserID, vh.client.DeviceID, txn.TheirUserID, txn.TheirDeviceID, myDeviceKeyID.String(), myDevice.SigningKey.String())
	if err != nil {
		return err
	}

	// Master signing key
	crossSigningKeys := vh.mach.GetOwnCrossSigningPublicKeys(ctx)
	if crossSigningKeys != nil {
		masterKey = crossSigningKeys.MasterKey.String()
		crossSigningKeyID := id.NewKeyID(id.KeyAlgorithmEd25519, masterKey)
		keys[crossSigningKeyID], err = vh.verificationMACHKDF(txn, vh.client.UserID, vh.client.DeviceID, txn.TheirUserID, txn.TheirDeviceID, crossSigningKeyID.String(), masterKey)
		if err != nil {
			return err
		}
	}

	var keyIDs []string
	for keyID := range keys {
		keyIDs = append(keyIDs, keyID.String())
	}
	slices.Sort(keyIDs)
	keysMAC, err := vh.verificationMACHKDF(txn, vh.client.UserID, vh.client.DeviceID, txn.TheirUserID, txn.TheirDeviceID, "KEY_IDS", strings.Join(keyIDs, ","))
	if err != nil {
		return err
	}

	macEventContent := &event.VerificationMACEventContent{
		Keys: keysMAC,
		MAC:  keys,
	}
	err = vh.sendVerificationEvent(ctx, txn, event.InRoomVerificationMAC, macEventContent)
	if err != nil {
		return err
	}
	log.Info().Msg("Sent our MAC event")

	txn.SentOurMAC = true
	if txn.ReceivedTheirMAC {
		txn.VerificationState = VerificationStateSASMACExchanged

		if err := vh.trustKeysAfterMACCheck(ctx, txn, masterKey); err != nil {
			return fmt.Errorf("failed to trust keys: %w", err)
		}

		err := vh.sendVerificationEvent(ctx, txn, event.InRoomVerificationDone, &event.VerificationDoneEventContent{})
		if err != nil {
			return err
		}
		txn.SentOurDone = true
	}
	return vh.store.SaveVerificationTransaction(ctx, txn)
}

// onVerificationStartSAS handles the m.key.verification.start events with
// method of m.sas.v1 by implementing steps 4-7 of [Section 11.12.2.2] of the
// Spec.
//
// [Section 11.12.2.2]: https://spec.matrix.org/v1.9/client-server-api/#short-authentication-string-sas-verification
func (vh *VerificationHelper) onVerificationStartSAS(ctx context.Context, txn VerificationTransaction, evt *event.Event) error {
	startEvt := evt.Content.AsVerificationStart()
	log := vh.getLog(ctx).With().
		Str("verification_action", "start SAS").
		Stringer("transaction_id", txn.TransactionID).
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("Received SAS verification start event")

	_, err := vh.mach.GetOrFetchDevice(ctx, evt.Sender, startEvt.FromDevice)
	if err != nil {
		log.Err(err).Msg("Failed to fetch device")
		return err
	}

	keyAggreementProtocol := event.KeyAgreementProtocolCurve25519HKDFSHA256
	if !slices.Contains(startEvt.KeyAgreementProtocols, keyAggreementProtocol) {
		return fmt.Errorf("the other device does not support any key agreement protocols that we support")
	}

	hashAlgorithm := event.VerificationHashMethodSHA256
	if !slices.Contains(startEvt.Hashes, hashAlgorithm) {
		return fmt.Errorf("the other device does not support any hash algorithms that we support")
	}

	macMethod := event.MACMethodHKDFHMACSHA256V2
	if !slices.Contains(startEvt.MessageAuthenticationCodes, macMethod) {
		if slices.Contains(startEvt.MessageAuthenticationCodes, event.MACMethodHKDFHMACSHA256) {
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
	txn.EphemeralKey = &ECDHPrivateKey{ephemeralKey}

	if !txn.StartedByUs {
		commitment, err := calculateCommitment(ephemeralKey.PublicKey(), txn)
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
		txn.VerificationState = VerificationStateSASAccepted
	}
	return vh.store.SaveVerificationTransaction(ctx, txn)
}

func calculateCommitment(ephemeralPubKey *ecdh.PublicKey, txn VerificationTransaction) ([]byte, error) {
	// The commitmentHashInput is the hash (encoded as unpadded base64) of the
	// concatenation of the device's ephemeral public key (encoded as
	// unpadded base64) and the canonical JSON representation of the
	// m.key.verification.start message.
	//
	// I have no idea why they chose to base64-encode the public key before
	// hashing it, but we are just stuck on that.
	commitmentHashInput := sha256.New()
	commitmentHashInput.Write([]byte(base64.RawStdEncoding.EncodeToString(ephemeralPubKey.Bytes())))
	encodedStartEvt, err := json.Marshal(txn.StartEventContent)
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
func (vh *VerificationHelper) onVerificationAccept(ctx context.Context, txn VerificationTransaction, evt *event.Event) {
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
	ctx = log.WithContext(ctx)
	log.Info().Msg("Received SAS verification accept event")

	vh.activeTransactionsLock.Lock()
	defer vh.activeTransactionsLock.Unlock()
	if txn.VerificationState != VerificationStateSASStarted {
		vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUnexpectedMessage,
			"received accept event for a transaction that is not in the started state")
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

	txn.VerificationState = VerificationStateSASAccepted
	txn.MACMethod = acceptEvt.MessageAuthenticationCode
	txn.Commitment = acceptEvt.Commitment
	txn.EphemeralKey = &ECDHPrivateKey{ephemeralKey}
	txn.EphemeralPublicKeyShared = true

	if err := vh.store.SaveVerificationTransaction(ctx, txn); err != nil {
		log.Err(err).Msg("failed to save verification transaction")
	}
}

func (vh *VerificationHelper) onVerificationKey(ctx context.Context, txn VerificationTransaction, evt *event.Event) {
	log := vh.getLog(ctx).With().
		Str("verification_action", "key").
		Logger()
	ctx = log.WithContext(ctx)
	keyEvt := evt.Content.AsVerificationKey()
	vh.activeTransactionsLock.Lock()
	defer vh.activeTransactionsLock.Unlock()

	if txn.VerificationState != VerificationStateSASAccepted {
		vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUnexpectedMessage,
			"received key event for a transaction that is not in the accepted state")
		return
	}

	var err error
	publicKey, err := ecdh.X25519().NewPublicKey(keyEvt.Key)
	if err != nil {
		log.Err(err).Msg("Failed to generate other public key")
		return
	}
	txn.OtherPublicKey = &ECDHPublicKey{publicKey}

	if txn.EphemeralPublicKeyShared {
		// Verify that the commitment hash is correct
		commitment, err := calculateCommitment(publicKey, txn)
		if err != nil {
			log.Err(err).Msg("Failed to calculate commitment")
			return
		}
		if !bytes.Equal(commitment, txn.Commitment) {
			vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeKeyMismatch, "The key was not the one we expected")
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
	txn.VerificationState = VerificationStateSASKeysExchanged

	sasBytes, err := vh.verificationSASHKDF(txn)
	if err != nil {
		log.Err(err).Msg("Failed to compute HKDF for SAS")
		return
	}

	var decimals []int
	var emojis []rune
	var emojiDescriptions []string
	if slices.Contains(txn.StartEventContent.ShortAuthenticationString, event.SASMethodDecimal) {
		decimals = []int{
			(int(sasBytes[0])<<5 | int(sasBytes[1])>>3) + 1000,
			((int(sasBytes[1])&0x07)<<10 | int(sasBytes[2])<<2 | int(sasBytes[3])>>6) + 1000,
			((int(sasBytes[3])&0x3f)<<7 | int(sasBytes[4])>>1) + 1000,
		}
	}
	if slices.Contains(txn.StartEventContent.ShortAuthenticationString, event.SASMethodEmoji) {
		sasNum := uint64(sasBytes[0])<<40 | uint64(sasBytes[1])<<32 | uint64(sasBytes[2])<<24 |
			uint64(sasBytes[3])<<16 | uint64(sasBytes[4])<<8 | uint64(sasBytes[5])

		for i := 0; i < 7; i++ {
			// Right shift the number and then mask the lowest 6 bits.
			emojiIdx := (sasNum >> uint(48-(i+1)*6)) & 0b111111
			emojis = append(emojis, allEmojis[emojiIdx])
			emojiDescriptions = append(emojiDescriptions, allEmojiDescriptions[emojiIdx])
		}
	}
	vh.showSAS(ctx, txn.TransactionID, emojis, emojiDescriptions, decimals)

	if err := vh.store.SaveVerificationTransaction(ctx, txn); err != nil {
		log.Err(err).Msg("failed to save verification transaction")
	}
}

func (vh *VerificationHelper) verificationSASHKDF(txn VerificationTransaction) ([]byte, error) {
	sharedSecret, err := txn.EphemeralKey.ECDH(txn.OtherPublicKey.PublicKey)
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
		txn.TheirUserID.String(),
		txn.TheirDeviceID.String(),
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

func (vh *VerificationHelper) verificationMACHKDF(txn VerificationTransaction, senderUser id.UserID, senderDevice id.DeviceID, receivingUser id.UserID, receivingDevice id.DeviceID, keyID, key string) ([]byte, error) {
	sharedSecret, err := txn.EphemeralKey.ECDH(txn.OtherPublicKey.PublicKey)
	if err != nil {
		return nil, err
	}

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
		sum, err = base64.RawStdEncoding.DecodeString(BrokenB64Encode(sum))
		if err != nil {
			panic(err)
		}
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

var allEmojiDescriptions = []string{
	"Dog",
	"Cat",
	"Lion",
	"Horse",
	"Unicorn",
	"Pig",
	"Elephant",
	"Rabbit",
	"Panda",
	"Rooster",
	"Penguin",
	"Turtle",
	"Fish",
	"Octopus",
	"Butterfly",
	"Flower",
	"Tree",
	"Cactus",
	"Mushroom",
	"Globe",
	"Moon",
	"Cloud",
	"Fire",
	"Banana",
	"Apple",
	"Strawberry",
	"Corn",
	"Pizza",
	"Cake",
	"Heart",
	"Smiley",
	"Robot",
	"Hat",
	"Glasses",
	"Spanner",
	"Santa",
	"Thumbs Up",
	"Umbrella",
	"Hourglass",
	"Clock",
	"Gift",
	"Light Bulb",
	"Book",
	"Pencil",
	"Paperclip",
	"Scissors",
	"Lock",
	"Key",
	"Hammer",
	"Telephone",
	"Flag",
	"Train",
	"Bicycle",
	"Aeroplane",
	"Rocket",
	"Trophy",
	"Ball",
	"Guitar",
	"Trumpet",
	"Bell",
	"Anchor",
	"Headphones",
	"Folder",
	"Pin",
}

func (vh *VerificationHelper) onVerificationMAC(ctx context.Context, txn VerificationTransaction, evt *event.Event) {
	log := vh.getLog(ctx).With().
		Str("verification_action", "mac").
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("Received SAS verification MAC event")
	vh.activeTransactionsLock.Lock()
	defer vh.activeTransactionsLock.Unlock()
	macEvt := evt.Content.AsVerificationMAC()

	// Verifying Keys MAC
	log.Info().Msg("Verifying MAC for all sent keys")
	var hasTheirDeviceKey bool
	var masterKey string
	var keyIDs []string
	for keyID := range macEvt.MAC {
		keyIDs = append(keyIDs, keyID.String())
		_, kID := keyID.Parse()
		if kID == txn.TheirDeviceID.String() {
			hasTheirDeviceKey = true
		} else {
			masterKey = kID
		}
	}
	slices.Sort(keyIDs)
	expectedKeyMAC, err := vh.verificationMACHKDF(txn, txn.TheirUserID, txn.TheirDeviceID, vh.client.UserID, vh.client.DeviceID, "KEY_IDS", strings.Join(keyIDs, ","))
	if err != nil {
		vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeSASMismatch, "failed to calculate key list MAC: %w", err)
		return
	}
	if !bytes.Equal(expectedKeyMAC, macEvt.Keys) {
		vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeSASMismatch, "key list MAC mismatch")
		return
	}
	if !hasTheirDeviceKey {
		vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeSASMismatch, "their device key not found in list of keys")
		return
	}

	// Verify the MAC for each key
	var theirDevice *id.Device
	for keyID, mac := range macEvt.MAC {
		log.Info().Str("key_id", keyID.String()).Msg("Received MAC for key")

		alg, kID := keyID.Parse()
		if alg != id.KeyAlgorithmEd25519 {
			vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUnknownMethod, "unsupported key algorithm %s", alg)
			return
		}

		var key string
		if kID == txn.TheirDeviceID.String() {
			if theirDevice != nil {
				vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeInvalidMessage, "two keys found for their device ID")
				return
			}
			theirDevice, err = vh.mach.GetOrFetchDevice(ctx, txn.TheirUserID, txn.TheirDeviceID)
			if err != nil {
				vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUser, "failed to fetch their device: %w", err)
				return
			}
			key = theirDevice.SigningKey.String()
		} else { // This is the master key
			crossSigningKeys := vh.mach.GetOwnCrossSigningPublicKeys(ctx)
			if crossSigningKeys == nil {
				vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUser, "cross-signing keys not found")
				return
			}
			if kID != crossSigningKeys.MasterKey.String() {
				vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUser, "unknown key ID %s", keyID)
				return
			}
			key = crossSigningKeys.MasterKey.String()
		}

		expectedMAC, err := vh.verificationMACHKDF(txn, txn.TheirUserID, txn.TheirDeviceID, vh.client.UserID, vh.client.DeviceID, keyID.String(), key)
		if err != nil {
			vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUser, "failed to calculate key MAC: %w", err)
			return
		}
		if subtle.ConstantTimeCompare(expectedMAC, mac) == 0 {
			vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeSASMismatch, "MAC mismatch for key %s", keyID)
			return
		}
	}
	log.Info().Msg("All MACs verified")

	txn.ReceivedTheirMAC = true
	if txn.SentOurMAC {
		txn.VerificationState = VerificationStateSASMACExchanged

		if err := vh.trustKeysAfterMACCheck(ctx, txn, masterKey); err != nil {
			vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUser, "failed to trust keys: %w", err)
			return
		}

		err := vh.sendVerificationEvent(ctx, txn, event.InRoomVerificationDone, &event.VerificationDoneEventContent{})
		if err != nil {
			vh.cancelVerificationTxn(ctx, txn, event.VerificationCancelCodeUser, "failed to send verification done event: %w", err)
			return
		}
		txn.SentOurDone = true
	}

	if err := vh.store.SaveVerificationTransaction(ctx, txn); err != nil {
		log.Err(err).Msg("failed to save verification transaction")
	}
}

func (vh *VerificationHelper) trustKeysAfterMACCheck(ctx context.Context, txn VerificationTransaction, masterKey string) error {
	theirDevice, err := vh.mach.GetOrFetchDevice(ctx, txn.TheirUserID, txn.TheirDeviceID)
	if err != nil {
		return fmt.Errorf("failed to fetch their device: %w", err)
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
	} else if masterKey != "" {
		// Cross-signing situation.
		//
		// The master key was included in the list of keys to verify, so verify
		// that it matches what we expect and sign their master key using the
		// user-signing key.
		theirSigningKeys, err := vh.mach.GetCrossSigningPublicKeys(ctx, txn.TheirUserID)
		if err != nil {
			return fmt.Errorf("couldn't get %s's cross-signing keys: %w", txn.TheirUserID, err)
		} else if theirSigningKeys.MasterKey.String() != masterKey {
			return fmt.Errorf("master keys do not match")
		}

		if err := vh.mach.SignUser(ctx, txn.TheirUserID, theirSigningKeys.MasterKey); err != nil {
			return fmt.Errorf("failed to sign %s's master key: %w", txn.TheirUserID, err)
		}
	}
	return nil
}
