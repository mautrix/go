package session

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"go.mau.fi/util/exerrors"

	"maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/crypto/goolm/goolmbase64"
	"maunium.net/go/mautrix/crypto/goolm/libolmpickle"
	"maunium.net/go/mautrix/crypto/goolm/megolm"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/id"
)

const (
	megolmOutboundSessionPickleVersion       byte   = 1
	megolmOutboundSessionPickleVersionLibOlm uint32 = 1
)

// MegolmOutboundSession stores information about the sessions to send.
type MegolmOutboundSession struct {
	Ratchet    megolm.Ratchet        `json:"ratchet"`
	SigningKey crypto.Ed25519KeyPair `json:"signing_key"`
}

var _ olm.OutboundGroupSession = (*MegolmOutboundSession)(nil)

// NewMegolmOutboundSession creates a new MegolmOutboundSession.
func NewMegolmOutboundSession() (*MegolmOutboundSession, error) {
	o := &MegolmOutboundSession{}
	var err error
	o.SigningKey, err = crypto.Ed25519GenerateKey()
	if err != nil {
		return nil, err
	}
	var randomData [megolm.RatchetParts * megolm.RatchetPartLength]byte
	_, err = rand.Read(randomData[:])
	if err != nil {
		return nil, err
	}
	ratchet, err := megolm.New(0, randomData)
	if err != nil {
		return nil, err
	}
	o.Ratchet = *ratchet
	return o, nil
}

// MegolmOutboundSessionFromPickled loads the MegolmOutboundSession details from a pickled base64 string. The input is decrypted with the supplied key.
func MegolmOutboundSessionFromPickled(pickled, key []byte) (*MegolmOutboundSession, error) {
	if len(pickled) == 0 {
		return nil, fmt.Errorf("megolmOutboundSessionFromPickled: %w", olm.ErrEmptyInput)
	}
	a := &MegolmOutboundSession{}
	err := a.Unpickle(pickled, key)
	return a, err
}

// Encrypt encrypts the plaintext as a base64 encoded group message.
func (o *MegolmOutboundSession) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, olm.ErrEmptyInput
	}
	encrypted, err := o.Ratchet.Encrypt(plaintext, o.SigningKey)
	return goolmbase64.Encode(encrypted), err
}

// SessionID returns the base64 endoded public signing key
func (o *MegolmOutboundSession) ID() id.SessionID {
	return id.SessionID(base64.RawStdEncoding.EncodeToString(o.SigningKey.PublicKey))
}

// PickleAsJSON returns an Session as a base64 string encrypted using the supplied key. The unencrypted representation of the Account is in JSON format.
func (o *MegolmOutboundSession) PickleAsJSON(key []byte) ([]byte, error) {
	return libolmpickle.PickleAsJSON(o, megolmOutboundSessionPickleVersion, key)
}

// UnpickleAsJSON updates an Session by a base64 encrypted string with the key. The unencrypted representation has to be in JSON format.
func (o *MegolmOutboundSession) UnpickleAsJSON(pickled, key []byte) error {
	return libolmpickle.UnpickleAsJSON(o, pickled, key, megolmOutboundSessionPickleVersion)
}

// Unpickle decodes the base64 encoded string and decrypts the result with the key.
// The decrypted value is then passed to UnpickleLibOlm.
func (o *MegolmOutboundSession) Unpickle(pickled, key []byte) error {
	if len(key) == 0 {
		return olm.ErrNoKeyProvided
	}
	decrypted, err := libolmpickle.Unpickle(key, pickled)
	if err != nil {
		return err
	}
	return o.UnpickleLibOlm(decrypted)
}

// UnpickleLibOlm unpickles the unencryted value and populates the
// [MegolmOutboundSession] accordingly.
func (o *MegolmOutboundSession) UnpickleLibOlm(buf []byte) error {
	decoder := libolmpickle.NewDecoder(buf)
	pickledVersion, err := decoder.ReadUInt32()
	if pickledVersion != megolmOutboundSessionPickleVersionLibOlm {
		return fmt.Errorf("unpickle MegolmInboundSession: %w (found version %d)", olm.ErrBadVersion, pickledVersion)
	}
	if err = o.Ratchet.UnpickleLibOlm(decoder); err != nil {
		return err
	}
	return o.SigningKey.UnpickleLibOlm(decoder)
}

// Pickle returns a base64 encoded and with key encrypted pickled MegolmOutboundSession using PickleLibOlm().
func (o *MegolmOutboundSession) Pickle(key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, olm.ErrNoKeyProvided
	}
	return libolmpickle.Pickle(key, o.PickleLibOlm())
}

// PickleLibOlm pickles the session returning the raw bytes.
func (o *MegolmOutboundSession) PickleLibOlm() []byte {
	encoder := libolmpickle.NewEncoder()
	encoder.WriteUInt32(megolmOutboundSessionPickleVersionLibOlm)
	o.Ratchet.PickleLibOlm(encoder)
	o.SigningKey.PickleLibOlm(encoder)
	return encoder.Bytes()
}

func (o *MegolmOutboundSession) SessionSharingMessage() ([]byte, error) {
	return o.Ratchet.SessionSharingMessage(o.SigningKey)
}

// MessageIndex returns the message index for this session.  Each message is
// sent with an increasing index; this returns the index for the next message.
func (s *MegolmOutboundSession) MessageIndex() uint {
	return uint(s.Ratchet.Counter)
}

// Key returns the base64-encoded current ratchet key for this session.
func (s *MegolmOutboundSession) Key() string {
	return string(exerrors.Must(s.SessionSharingMessage()))
}
