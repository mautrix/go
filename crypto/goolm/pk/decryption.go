package pk

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/element-hq/mautrix-go/crypto/goolm"
	"github.com/element-hq/mautrix-go/crypto/goolm/cipher"
	"github.com/element-hq/mautrix-go/crypto/goolm/crypto"
	"github.com/element-hq/mautrix-go/crypto/goolm/libolmpickle"
	"github.com/element-hq/mautrix-go/crypto/goolm/utilities"
	"github.com/element-hq/mautrix-go/id"
)

const (
	decryptionPickleVersionJSON   uint8  = 1
	decryptionPickleVersionLibOlm uint32 = 1
)

// Decryption is used to decrypt pk messages
type Decryption struct {
	KeyPair crypto.Curve25519KeyPair `json:"key_pair"`
}

// NewDecryption returns a new Decryption with a new generated key pair.
func NewDecryption() (*Decryption, error) {
	keyPair, err := crypto.Curve25519GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return &Decryption{
		KeyPair: keyPair,
	}, nil
}

// NewDescriptionFromPrivate resturns a new Decryption with the private key fixed.
func NewDecryptionFromPrivate(privateKey crypto.Curve25519PrivateKey) (*Decryption, error) {
	s := &Decryption{}
	keyPair, err := crypto.Curve25519GenerateFromPrivate(privateKey)
	if err != nil {
		return nil, err
	}
	s.KeyPair = keyPair
	return s, nil
}

// PubKey returns the public key base 64 encoded.
func (s Decryption) PubKey() id.Curve25519 {
	return s.KeyPair.B64Encoded()
}

// PrivateKey returns the private key.
func (s Decryption) PrivateKey() crypto.Curve25519PrivateKey {
	return s.KeyPair.PrivateKey
}

// Decrypt decrypts the ciphertext and verifies the MAC. The base64 encoded key is used to construct the shared secret.
func (s Decryption) Decrypt(ciphertext, mac []byte, key id.Curve25519) ([]byte, error) {
	keyDecoded, err := base64.RawStdEncoding.DecodeString(string(key))
	if err != nil {
		return nil, err
	}
	sharedSecret, err := s.KeyPair.SharedSecret(keyDecoded)
	if err != nil {
		return nil, err
	}
	decodedMAC, err := goolm.Base64Decode(mac)
	if err != nil {
		return nil, err
	}
	cipher := cipher.NewAESSHA256(nil)
	verified, err := cipher.Verify(sharedSecret, ciphertext, decodedMAC)
	if err != nil {
		return nil, err
	}
	if !verified {
		return nil, fmt.Errorf("decrypt: %w", goolm.ErrBadMAC)
	}
	plaintext, err := cipher.Decrypt(sharedSecret, ciphertext)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// PickleAsJSON returns an Decryption as a base64 string encrypted using the supplied key. The unencrypted representation of the Account is in JSON format.
func (a Decryption) PickleAsJSON(key []byte) ([]byte, error) {
	return utilities.PickleAsJSON(a, decryptionPickleVersionJSON, key)
}

// UnpickleAsJSON updates an Decryption by a base64 encrypted string using the supplied key. The unencrypted representation has to be in JSON format.
func (a *Decryption) UnpickleAsJSON(pickled, key []byte) error {
	return utilities.UnpickleAsJSON(a, pickled, key, decryptionPickleVersionJSON)
}

// Unpickle decodes the base64 encoded string and decrypts the result with the key.
// The decrypted value is then passed to UnpickleLibOlm.
func (a *Decryption) Unpickle(pickled, key []byte) error {
	decrypted, err := cipher.Unpickle(key, pickled)
	if err != nil {
		return err
	}
	_, err = a.UnpickleLibOlm(decrypted)
	return err
}

// UnpickleLibOlm decodes the unencryted value and populates the Decryption accordingly. It returns the number of bytes read.
func (a *Decryption) UnpickleLibOlm(value []byte) (int, error) {
	//First 4 bytes are the accountPickleVersion
	pickledVersion, curPos, err := libolmpickle.UnpickleUInt32(value)
	if err != nil {
		return 0, err
	}
	switch pickledVersion {
	case decryptionPickleVersionLibOlm:
	default:
		return 0, fmt.Errorf("unpickle olmSession: %w", goolm.ErrBadVersion)
	}
	readBytes, err := a.KeyPair.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	return curPos, nil
}

// Pickle returns a base64 encoded and with key encrypted pickled Decryption using PickleLibOlm().
func (a Decryption) Pickle(key []byte) ([]byte, error) {
	pickeledBytes := make([]byte, a.PickleLen())
	written, err := a.PickleLibOlm(pickeledBytes)
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

// PickleLibOlm encodes the Decryption into target. target has to have a size of at least PickleLen() and is written to from index 0.
// It returns the number of bytes written.
func (a Decryption) PickleLibOlm(target []byte) (int, error) {
	if len(target) < a.PickleLen() {
		return 0, fmt.Errorf("pickle Decryption: %w", goolm.ErrValueTooShort)
	}
	written := libolmpickle.PickleUInt32(decryptionPickleVersionLibOlm, target)
	writtenKey, err := a.KeyPair.PickleLibOlm(target[written:])
	if err != nil {
		return 0, fmt.Errorf("pickle Decryption: %w", err)
	}
	written += writtenKey
	return written, nil
}

// PickleLen returns the number of bytes the pickled Decryption will have.
func (a Decryption) PickleLen() int {
	length := libolmpickle.PickleUInt32Len(decryptionPickleVersionLibOlm)
	length += a.KeyPair.PickleLen()
	return length
}
