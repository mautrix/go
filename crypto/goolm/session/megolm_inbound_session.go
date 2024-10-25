package session

import (
	"encoding/base64"
	"fmt"

	"maunium.net/go/mautrix/crypto/goolm/cipher"
	"maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/crypto/goolm/goolmbase64"
	"maunium.net/go/mautrix/crypto/goolm/libolmpickle"
	"maunium.net/go/mautrix/crypto/goolm/megolm"
	"maunium.net/go/mautrix/crypto/goolm/message"
	"maunium.net/go/mautrix/crypto/goolm/utilities"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/id"
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

// Ensure that MegolmInboundSession implements the [olm.InboundGroupSession]
// interface.
var _ olm.InboundGroupSession = (*MegolmInboundSession)(nil)

// NewMegolmInboundSession creates a new MegolmInboundSession from a base64 encoded session sharing message.
func NewMegolmInboundSession(input []byte) (*MegolmInboundSession, error) {
	var err error
	input, err = goolmbase64.Decode(input)
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
	input, err = goolmbase64.Decode(input)
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
		return nil, fmt.Errorf("megolmInboundSessionFromPickled: %w", olm.ErrEmptyInput)
	}
	a := &MegolmInboundSession{}
	err := a.Unpickle(pickled, key)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// getRatchet tries to find the correct ratchet for a messageIndex.
func (o *MegolmInboundSession) getRatchet(messageIndex uint32) (*megolm.Ratchet, error) {
	// pick a megolm instance to use. if we are at or beyond the latest ratchet value, use that
	if (messageIndex - o.Ratchet.Counter) < uint32(1<<31) {
		o.Ratchet.AdvanceTo(messageIndex)
		return &o.Ratchet, nil
	}
	if (messageIndex - o.InitialRatchet.Counter) >= uint32(1<<31) {
		// the counter is before our initial ratchet - we can't decode this
		return nil, fmt.Errorf("decrypt: %w", olm.ErrRatchetNotAvailable)
	}
	// otherwise, start from the initial ratchet. Take a copy so that we don't overwrite the initial ratchet
	copiedRatchet := o.InitialRatchet
	copiedRatchet.AdvanceTo(messageIndex)
	return &copiedRatchet, nil

}

// Decrypt decrypts a base64 encoded group message.
func (o *MegolmInboundSession) Decrypt(ciphertext []byte) ([]byte, uint, error) {
	if len(ciphertext) == 0 {
		return nil, 0, olm.ErrEmptyInput
	}
	if o.SigningKey == nil {
		return nil, 0, fmt.Errorf("decrypt: %w", olm.ErrBadMessageFormat)
	}
	decoded, err := goolmbase64.Decode(ciphertext)
	if err != nil {
		return nil, 0, err
	}
	msg := &message.GroupMessage{}
	err = msg.Decode(decoded)
	if err != nil {
		return nil, 0, err
	}
	if msg.Version != protocolVersion {
		return nil, 0, fmt.Errorf("decrypt: %w", olm.ErrWrongProtocolVersion)
	}
	if msg.Ciphertext == nil || !msg.HasMessageIndex {
		return nil, 0, fmt.Errorf("decrypt: %w", olm.ErrBadMessageFormat)
	}

	// verify signature
	verifiedSignature := msg.VerifySignatureInline(o.SigningKey, decoded)
	if !verifiedSignature {
		return nil, 0, fmt.Errorf("decrypt: %w", olm.ErrBadSignature)
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
	return decrypted, uint(msg.MessageIndex), nil

}

// ID returns the base64 endoded signing key
func (o *MegolmInboundSession) ID() id.SessionID {
	return id.SessionID(base64.RawStdEncoding.EncodeToString(o.SigningKey))
}

// PickleAsJSON returns an MegolmInboundSession as a base64 string encrypted using the supplied key. The unencrypted representation of the Account is in JSON format.
func (o *MegolmInboundSession) PickleAsJSON(key []byte) ([]byte, error) {
	return utilities.PickleAsJSON(o, megolmInboundSessionPickleVersionJSON, key)
}

// UnpickleAsJSON updates an MegolmInboundSession by a base64 encrypted string using the supplied key. The unencrypted representation has to be in JSON format.
func (o *MegolmInboundSession) UnpickleAsJSON(pickled, key []byte) error {
	return utilities.UnpickleAsJSON(o, pickled, key, megolmInboundSessionPickleVersionJSON)
}

// Export returns the base64-encoded ratchet key for this session, at the given
// index, in a format which can be used by
// InboundGroupSession.InboundGroupSessionImport().  Encrypts the
// InboundGroupSession using the supplied key.  Returns error on failure.
// if we do not have a session key corresponding to the given index (ie, it was
// sent before the session key was shared with us) the error will be
// returned.
func (o *MegolmInboundSession) Export(messageIndex uint32) ([]byte, error) {
	ratchet, err := o.getRatchet(messageIndex)
	if err != nil {
		return nil, err
	}
	return ratchet.SessionExportMessage(o.SigningKey)
}

// Unpickle decodes the base64 encoded string and decrypts the result with the key.
// The decrypted value is then passed to UnpickleLibOlm.
func (o *MegolmInboundSession) Unpickle(pickled, key []byte) error {
	if len(key) == 0 {
		return olm.ErrNoKeyProvided
	} else if len(pickled) == 0 {
		return olm.ErrEmptyInput
	}
	decrypted, err := cipher.Unpickle(key, pickled)
	if err != nil {
		return err
	}
	return o.UnpickleLibOlm(decrypted)
}

// UnpickleLibOlm unpickles the unencryted value and populates the [Session]
// accordingly.
func (o *MegolmInboundSession) UnpickleLibOlm(value []byte) error {
	decoder := libolmpickle.NewDecoder(value)
	pickledVersion, err := decoder.ReadUInt32()
	if err != nil {
		return err
	}
	if pickledVersion != megolmInboundSessionPickleVersionLibOlm && pickledVersion != 1 {
		return fmt.Errorf("unpickle MegolmInboundSession: %w (found version %d)", olm.ErrBadVersion, pickledVersion)
	}

	if err = o.InitialRatchet.UnpickleLibOlm(decoder); err != nil {
		return err
	} else if err = o.Ratchet.UnpickleLibOlm(decoder); err != nil {
		return err
	} else if err = o.SigningKey.UnpickleLibOlm(decoder); err != nil {
		return err
	}

	if pickledVersion == 1 {
		// pickle v1 had no signing_key_verified field (all keyshares were verified at import time)
		o.SigningKeyVerified = true
	} else {
		o.SigningKeyVerified, err = decoder.ReadBool()
		return err
	}
	return nil
}

// Pickle returns a base64 encoded and with key encrypted pickled MegolmInboundSession using PickleLibOlm().
func (o *MegolmInboundSession) Pickle(key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, olm.ErrNoKeyProvided
	}
	return cipher.Pickle(key, o.PickleLibOlm())
}

// PickleLibOlm pickles the session returning the raw bytes.
func (o *MegolmInboundSession) PickleLibOlm() []byte {
	encoder := libolmpickle.NewEncoder()
	encoder.WriteUInt32(megolmInboundSessionPickleVersionLibOlm)
	o.InitialRatchet.PickleLibOlm(encoder)
	o.Ratchet.PickleLibOlm(encoder)
	o.SigningKey.PickleLibOlm(encoder)
	encoder.WriteBool(o.SigningKeyVerified)
	return encoder.Bytes()
}

// FirstKnownIndex returns the first message index we know how to decrypt.
func (s *MegolmInboundSession) FirstKnownIndex() uint32 {
	return s.InitialRatchet.Counter
}

// IsVerified check if the session has been verified as a valid session.  (A
// session is verified either because the original session share was signed, or
// because we have subsequently successfully decrypted a message.)
func (s *MegolmInboundSession) IsVerified() bool {
	return s.SigningKeyVerified
}
