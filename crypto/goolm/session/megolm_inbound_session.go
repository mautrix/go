package session

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/element-hq/mautrix-go/crypto/goolm"
	"github.com/element-hq/mautrix-go/crypto/goolm/cipher"
	"github.com/element-hq/mautrix-go/crypto/goolm/crypto"
	"github.com/element-hq/mautrix-go/crypto/goolm/libolmpickle"
	"github.com/element-hq/mautrix-go/crypto/goolm/megolm"
	"github.com/element-hq/mautrix-go/crypto/goolm/message"
	"github.com/element-hq/mautrix-go/crypto/goolm/utilities"
	"github.com/element-hq/mautrix-go/id"
)

const (
	megolmInboundSessionPickleVersionJSON   byte   = 1
	megolmInboundSessionPickleVersionLibOlm uint32 = 2
)

// MegolmInboundSession stores information about the sessions of receive.
type MegolmInboundSession struct {
	Ratchet            megolm.Ratchet          `json:"ratchet"`
	SigningKey         crypto.Ed25519PublicKey `json:"signing_key"`
	InitialRatchet     megolm.Ratchet          `json:"initial_ratchet"`
	SigningKeyVerified bool                    `json:"signing_key_verified"` //not used for now
}

// NewMegolmInboundSession creates a new MegolmInboundSession from a base64 encoded session sharing message.
func NewMegolmInboundSession(input []byte) (*MegolmInboundSession, error) {
	var err error
	input, err = goolm.Base64Decode(input)
	if err != nil {
		return nil, err
	}
	msg := message.MegolmSessionSharing{}
	err = msg.VerifyAndDecode(input)
	if err != nil {
		return nil, err
	}
	o := &MegolmInboundSession{}
	o.SigningKey = msg.PublicKey
	o.SigningKeyVerified = true
	ratchet, err := megolm.New(msg.Counter, msg.RatchetData)
	if err != nil {
		return nil, err
	}
	o.Ratchet = *ratchet
	o.InitialRatchet = *ratchet
	return o, nil
}

// NewMegolmInboundSessionFromExport creates a new MegolmInboundSession from a base64 encoded session export message.
func NewMegolmInboundSessionFromExport(input []byte) (*MegolmInboundSession, error) {
	var err error
	input, err = goolm.Base64Decode(input)
	if err != nil {
		return nil, err
	}
	msg := message.MegolmSessionExport{}
	err = msg.Decode(input)
	if err != nil {
		return nil, err
	}
	o := &MegolmInboundSession{}
	o.SigningKey = msg.PublicKey
	ratchet, err := megolm.New(msg.Counter, msg.RatchetData)
	if err != nil {
		return nil, err
	}
	o.Ratchet = *ratchet
	o.InitialRatchet = *ratchet
	return o, nil
}

// MegolmInboundSessionFromPickled loads the MegolmInboundSession details from a pickled base64 string. The input is decrypted with the supplied key.
func MegolmInboundSessionFromPickled(pickled, key []byte) (*MegolmInboundSession, error) {
	if len(pickled) == 0 {
		return nil, fmt.Errorf("megolmInboundSessionFromPickled: %w", goolm.ErrEmptyInput)
	}
	a := &MegolmInboundSession{}
	err := a.Unpickle(pickled, key)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// getRatchet tries to find the correct ratchet for a messageIndex.
func (o MegolmInboundSession) getRatchet(messageIndex uint32) (*megolm.Ratchet, error) {
	// pick a megolm instance to use. if we are at or beyond the latest ratchet value, use that
	if (messageIndex - o.Ratchet.Counter) < uint32(1<<31) {
		o.Ratchet.AdvanceTo(messageIndex)
		return &o.Ratchet, nil
	}
	if (messageIndex - o.InitialRatchet.Counter) >= uint32(1<<31) {
		// the counter is before our initial ratchet - we can't decode this
		return nil, fmt.Errorf("decrypt: %w", goolm.ErrRatchetNotAvailable)
	}
	// otherwise, start from the initial ratchet. Take a copy so that we don't overwrite the initial ratchet
	copiedRatchet := o.InitialRatchet
	copiedRatchet.AdvanceTo(messageIndex)
	return &copiedRatchet, nil

}

// Decrypt decrypts a base64 encoded group message.
func (o *MegolmInboundSession) Decrypt(ciphertext []byte) ([]byte, uint32, error) {
	if o.SigningKey == nil {
		return nil, 0, fmt.Errorf("decrypt: %w", goolm.ErrBadMessageFormat)
	}
	decoded, err := goolm.Base64Decode(ciphertext)
	if err != nil {
		return nil, 0, err
	}
	msg := &message.GroupMessage{}
	err = msg.Decode(decoded)
	if err != nil {
		return nil, 0, err
	}
	if msg.Version != protocolVersion {
		return nil, 0, fmt.Errorf("decrypt: %w", goolm.ErrWrongProtocolVersion)
	}
	if msg.Ciphertext == nil || !msg.HasMessageIndex {
		return nil, 0, fmt.Errorf("decrypt: %w", goolm.ErrBadMessageFormat)
	}

	// verify signature
	verifiedSignature := msg.VerifySignatureInline(o.SigningKey, decoded)
	if !verifiedSignature {
		return nil, 0, fmt.Errorf("decrypt: %w", goolm.ErrBadSignature)
	}

	targetRatch, err := o.getRatchet(msg.MessageIndex)
	if err != nil {
		return nil, 0, err
	}

	decrypted, err := targetRatch.Decrypt(decoded, &o.SigningKey, msg)
	if err != nil {
		return nil, 0, err
	}
	o.SigningKeyVerified = true
	return decrypted, msg.MessageIndex, nil

}

// SessionID returns the base64 endoded signing key
func (o MegolmInboundSession) SessionID() id.SessionID {
	return id.SessionID(base64.RawStdEncoding.EncodeToString(o.SigningKey))
}

// PickleAsJSON returns an MegolmInboundSession as a base64 string encrypted using the supplied key. The unencrypted representation of the Account is in JSON format.
func (o MegolmInboundSession) PickleAsJSON(key []byte) ([]byte, error) {
	return utilities.PickleAsJSON(o, megolmInboundSessionPickleVersionJSON, key)
}

// UnpickleAsJSON updates an MegolmInboundSession by a base64 encrypted string using the supplied key. The unencrypted representation has to be in JSON format.
func (o *MegolmInboundSession) UnpickleAsJSON(pickled, key []byte) error {
	return utilities.UnpickleAsJSON(o, pickled, key, megolmInboundSessionPickleVersionJSON)
}

// SessionExportMessage creates an base64 encoded export of the session.
func (o MegolmInboundSession) SessionExportMessage(messageIndex uint32) ([]byte, error) {
	ratchet, err := o.getRatchet(messageIndex)
	if err != nil {
		return nil, err
	}
	return ratchet.SessionExportMessage(o.SigningKey)
}

// Unpickle decodes the base64 encoded string and decrypts the result with the key.
// The decrypted value is then passed to UnpickleLibOlm.
func (o *MegolmInboundSession) Unpickle(pickled, key []byte) error {
	decrypted, err := cipher.Unpickle(key, pickled)
	if err != nil {
		return err
	}
	_, err = o.UnpickleLibOlm(decrypted)
	return err
}

// UnpickleLibOlm decodes the unencryted value and populates the Session accordingly. It returns the number of bytes read.
func (o *MegolmInboundSession) UnpickleLibOlm(value []byte) (int, error) {
	//First 4 bytes are the accountPickleVersion
	pickledVersion, curPos, err := libolmpickle.UnpickleUInt32(value)
	if err != nil {
		return 0, err
	}
	switch pickledVersion {
	case megolmInboundSessionPickleVersionLibOlm, 1:
	default:
		return 0, fmt.Errorf("unpickle MegolmInboundSession: %w", goolm.ErrBadVersion)
	}
	readBytes, err := o.InitialRatchet.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	readBytes, err = o.Ratchet.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	readBytes, err = o.SigningKey.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	if pickledVersion == 1 {
		// pickle v1 had no signing_key_verified field (all keyshares were verified at import time)
		o.SigningKeyVerified = true
	} else {
		o.SigningKeyVerified, readBytes, err = libolmpickle.UnpickleBool(value[curPos:])
		if err != nil {
			return 0, err
		}
		curPos += readBytes
	}
	return curPos, nil
}

// Pickle returns a base64 encoded and with key encrypted pickled MegolmInboundSession using PickleLibOlm().
func (o MegolmInboundSession) Pickle(key []byte) ([]byte, error) {
	pickeledBytes := make([]byte, o.PickleLen())
	written, err := o.PickleLibOlm(pickeledBytes)
	if err != nil {
		return nil, err
	}
	if written != len(pickeledBytes) {
		return nil, errors.New("number of written bytes not correct")
	}
	encrypted, err := cipher.Pickle(key, pickeledBytes)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

// PickleLibOlm encodes the session into target. target has to have a size of at least PickleLen() and is written to from index 0.
// It returns the number of bytes written.
func (o MegolmInboundSession) PickleLibOlm(target []byte) (int, error) {
	if len(target) < o.PickleLen() {
		return 0, fmt.Errorf("pickle MegolmInboundSession: %w", goolm.ErrValueTooShort)
	}
	written := libolmpickle.PickleUInt32(megolmInboundSessionPickleVersionLibOlm, target)
	writtenInitRatchet, err := o.InitialRatchet.PickleLibOlm(target[written:])
	if err != nil {
		return 0, fmt.Errorf("pickle MegolmInboundSession: %w", err)
	}
	written += writtenInitRatchet
	writtenRatchet, err := o.Ratchet.PickleLibOlm(target[written:])
	if err != nil {
		return 0, fmt.Errorf("pickle MegolmInboundSession: %w", err)
	}
	written += writtenRatchet
	writtenPubKey, err := o.SigningKey.PickleLibOlm(target[written:])
	if err != nil {
		return 0, fmt.Errorf("pickle MegolmInboundSession: %w", err)
	}
	written += writtenPubKey
	written += libolmpickle.PickleBool(o.SigningKeyVerified, target[written:])
	return written, nil
}

// PickleLen returns the number of bytes the pickled session will have.
func (o MegolmInboundSession) PickleLen() int {
	length := libolmpickle.PickleUInt32Len(megolmInboundSessionPickleVersionLibOlm)
	length += o.InitialRatchet.PickleLen()
	length += o.Ratchet.PickleLen()
	length += o.SigningKey.PickleLen()
	length += libolmpickle.PickleBoolLen(o.SigningKeyVerified)
	return length
}
