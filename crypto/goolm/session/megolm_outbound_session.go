package session

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"go.mau.fi/util/exerrors"

	"maunium.net/go/mautrix/crypto/goolm/cipher"
	"maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/crypto/goolm/goolmbase64"
	"maunium.net/go/mautrix/crypto/goolm/libolmpickle"
	"maunium.net/go/mautrix/crypto/goolm/megolm"
	"maunium.net/go/mautrix/crypto/goolm/utilities"
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
	o.SigningKey, err = crypto.Ed25519GenerateKey(nil)
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
	encrypted, err := o.Ratchet.Encrypt(plaintext, &o.SigningKey)
	if err != nil {
		return nil, err
	}
	return goolmbase64.Encode(encrypted), nil
}

// SessionID returns the base64 endoded public signing key
func (o *MegolmOutboundSession) ID() id.SessionID {
	return id.SessionID(base64.RawStdEncoding.EncodeToString(o.SigningKey.PublicKey))
}

// PickleAsJSON returns an Session as a base64 string encrypted using the supplied key. The unencrypted representation of the Account is in JSON format.
func (o *MegolmOutboundSession) PickleAsJSON(key []byte) ([]byte, error) {
	return utilities.PickleAsJSON(o, megolmOutboundSessionPickleVersion, key)
}

// UnpickleAsJSON updates an Session by a base64 encrypted string with the key. The unencrypted representation has to be in JSON format.
func (o *MegolmOutboundSession) UnpickleAsJSON(pickled, key []byte) error {
	return utilities.UnpickleAsJSON(o, pickled, key, megolmOutboundSessionPickleVersion)
}

// Unpickle decodes the base64 encoded string and decrypts the result with the key.
// The decrypted value is then passed to UnpickleLibOlm.
func (o *MegolmOutboundSession) Unpickle(pickled, key []byte) error {
	if len(key) == 0 {
		return olm.ErrNoKeyProvided
	}
	decrypted, err := cipher.Unpickle(key, pickled)
	if err != nil {
		return err
	}
	_, err = o.UnpickleLibOlm(decrypted)
	return err
}

// UnpickleLibOlm decodes the unencryted value and populates the Session accordingly. It returns the number of bytes read.
func (o *MegolmOutboundSession) UnpickleLibOlm(value []byte) (int, error) {
	//First 4 bytes are the accountPickleVersion
	pickledVersion, curPos, err := libolmpickle.UnpickleUInt32(value)
	if err != nil {
		return 0, err
	}
	switch pickledVersion {
	case megolmOutboundSessionPickleVersionLibOlm:
	default:
		return 0, fmt.Errorf("unpickle MegolmInboundSession: %w", olm.ErrBadVersion)
	}
	readBytes, err := o.Ratchet.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	readBytes, err = o.SigningKey.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	return curPos, nil
}

// Pickle returns a base64 encoded and with key encrypted pickled MegolmOutboundSession using PickleLibOlm().
func (o *MegolmOutboundSession) Pickle(key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, olm.ErrNoKeyProvided
	}
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
func (o *MegolmOutboundSession) PickleLibOlm(target []byte) (int, error) {
	if len(target) < o.PickleLen() {
		return 0, fmt.Errorf("pickle MegolmOutboundSession: %w", olm.ErrValueTooShort)
	}
	written := libolmpickle.PickleUInt32(megolmOutboundSessionPickleVersionLibOlm, target)
	writtenRatchet, err := o.Ratchet.PickleLibOlm(target[written:])
	if err != nil {
		return 0, fmt.Errorf("pickle MegolmOutboundSession: %w", err)
	}
	written += writtenRatchet
	writtenPubKey, err := o.SigningKey.PickleLibOlm(target[written:])
	if err != nil {
		return 0, fmt.Errorf("pickle MegolmOutboundSession: %w", err)
	}
	written += writtenPubKey
	return written, nil
}

// PickleLen returns the number of bytes the pickled session will have.
func (o *MegolmOutboundSession) PickleLen() int {
	length := libolmpickle.PickleUInt32Len(megolmOutboundSessionPickleVersionLibOlm)
	length += o.Ratchet.PickleLen()
	length += o.SigningKey.PickleLen()
	return length
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
