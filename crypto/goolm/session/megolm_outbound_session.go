package session

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/element-hq/mautrix-go/id"

	"github.com/element-hq/mautrix-go/crypto/goolm"
	"github.com/element-hq/mautrix-go/crypto/goolm/cipher"
	"github.com/element-hq/mautrix-go/crypto/goolm/crypto"
	"github.com/element-hq/mautrix-go/crypto/goolm/libolmpickle"
	"github.com/element-hq/mautrix-go/crypto/goolm/megolm"
	"github.com/element-hq/mautrix-go/crypto/goolm/utilities"
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
		return nil, fmt.Errorf("megolmOutboundSessionFromPickled: %w", goolm.ErrEmptyInput)
	}
	a := &MegolmOutboundSession{}
	err := a.Unpickle(pickled, key)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// Encrypt encrypts the plaintext as a base64 encoded group message.
func (o *MegolmOutboundSession) Encrypt(plaintext []byte) ([]byte, error) {
	encrypted, err := o.Ratchet.Encrypt(plaintext, &o.SigningKey)
	if err != nil {
		return nil, err
	}
	return goolm.Base64Encode(encrypted), nil
}

// SessionID returns the base64 endoded public signing key
func (o MegolmOutboundSession) SessionID() id.SessionID {
	return id.SessionID(base64.RawStdEncoding.EncodeToString(o.SigningKey.PublicKey))
}

// PickleAsJSON returns an Session as a base64 string encrypted using the supplied key. The unencrypted representation of the Account is in JSON format.
func (o MegolmOutboundSession) PickleAsJSON(key []byte) ([]byte, error) {
	return utilities.PickleAsJSON(o, megolmOutboundSessionPickleVersion, key)
}

// UnpickleAsJSON updates an Session by a base64 encrypted string with the key. The unencrypted representation has to be in JSON format.
func (o *MegolmOutboundSession) UnpickleAsJSON(pickled, key []byte) error {
	return utilities.UnpickleAsJSON(o, pickled, key, megolmOutboundSessionPickleVersion)
}

// Unpickle decodes the base64 encoded string and decrypts the result with the key.
// The decrypted value is then passed to UnpickleLibOlm.
func (o *MegolmOutboundSession) Unpickle(pickled, key []byte) error {
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
		return 0, fmt.Errorf("unpickle MegolmInboundSession: %w", goolm.ErrBadVersion)
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
func (o MegolmOutboundSession) Pickle(key []byte) ([]byte, error) {
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
func (o MegolmOutboundSession) PickleLibOlm(target []byte) (int, error) {
	if len(target) < o.PickleLen() {
		return 0, fmt.Errorf("pickle MegolmOutboundSession: %w", goolm.ErrValueTooShort)
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
func (o MegolmOutboundSession) PickleLen() int {
	length := libolmpickle.PickleUInt32Len(megolmOutboundSessionPickleVersionLibOlm)
	length += o.Ratchet.PickleLen()
	length += o.SigningKey.PickleLen()
	return length
}

func (o MegolmOutboundSession) SessionSharingMessage() ([]byte, error) {
	return o.Ratchet.SessionSharingMessage(o.SigningKey)
}
