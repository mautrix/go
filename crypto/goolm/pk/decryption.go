package pk

import (
	"codeberg.org/DerLukas/goolm"
	"codeberg.org/DerLukas/goolm/cipher"
	"codeberg.org/DerLukas/goolm/crypto"
	libolmpickle "codeberg.org/DerLukas/goolm/libolmPickle"
	"codeberg.org/DerLukas/goolm/utilities"
	"github.com/pkg/errors"
	"maunium.net/go/mautrix/id"
)

const (
	decryptionPickleVersionJSON   uint8  = 1
	decryptionPickleVersionLibOlm uint32 = 1
)

// Decription is used to decrypt pk messages
type Decription struct {
	KeyPair crypto.Curve25519KeyPair `json:"keyPair"`
}

// NewDecription returns a new Decription with a new generated key pair.
func NewDecription() (*Decription, error) {
	keyPair, err := crypto.Curve25519GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return &Decription{
		KeyPair: keyPair,
	}, nil
}

// NewDescriptionFromPrivate resturns a new Decription with the private key fixed.
func NewDecriptionFromPrivate(privateKey crypto.Curve25519PrivateKey) (*Decription, error) {
	s := &Decription{}
	keyPair, err := crypto.Curve25519GenerateFromPrivate(privateKey)
	if err != nil {
		return nil, err
	}
	s.KeyPair = keyPair
	return s, nil
}

// PubKey returns the public key base 64 encoded.
func (s Decription) PubKey() id.Curve25519 {
	return s.KeyPair.B64Encoded()
}

// PrivateKey returns the private key.
func (s Decription) PrivateKey() crypto.Curve25519PrivateKey {
	return s.KeyPair.PrivateKey
}

// Decrypt decrypts the ciphertext and verifies the MAC. The base64 encoded key is used to construct the shared secret.
func (s Decription) Decrypt(ciphertext, mac []byte, key id.Curve25519) ([]byte, error) {
	keyDecoded, err := goolm.Base64Decode([]byte(key))
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
	cipher := cipher.NewAESSha256(nil)
	verified, err := cipher.Verify(sharedSecret, ciphertext, decodedMAC)
	if err != nil {
		return nil, err
	}
	if !verified {
		return nil, errors.Wrap(goolm.ErrBadMAC, "decrypt")
	}
	plaintext, err := cipher.Decrypt(sharedSecret, ciphertext)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// PickleAsJSON returns an Decription as a base64 string encrypted using the supplied key. The unencrypted representation of the Account is in JSON format.
func (a Decription) PickleAsJSON(key []byte) ([]byte, error) {
	return utilities.PickleAsJSON(a, decryptionPickleVersionJSON, key)
}

// UnpickleAsJSON updates an Decription by a base64 encrypted string using the supplied key. The unencrypted representation has to be in JSON format.
func (a *Decription) UnpickleAsJSON(pickled, key []byte) error {
	return utilities.UnpickleAsJSON(a, pickled, key, decryptionPickleVersionJSON)
}

// Unpickle decodes the base64 encoded string and decrypts the result with the key.
// The decrypted value is then passed to UnpickleLibOlm.
func (a *Decription) Unpickle(pickled, key []byte) error {
	decrypted, err := cipher.Unpickle(key, pickled)
	if err != nil {
		return err
	}
	_, err = a.UnpickleLibOlm(decrypted)
	return err
}

// UnpickleLibOlm decodes the unencryted value and populates the Decription accordingly. It returns the number of bytes read.
func (a *Decription) UnpickleLibOlm(value []byte) (int, error) {
	//First 4 bytes are the accountPickleVersion
	pickledVersion, curPos, err := libolmpickle.UnpickleUInt32(value)
	if err != nil {
		return 0, err
	}
	switch pickledVersion {
	case decryptionPickleVersionLibOlm:
	default:
		return 0, errors.Wrap(goolm.ErrBadVersion, "unpickle olmSession")
	}
	readBytes, err := a.KeyPair.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	return curPos, nil
}

// Pickle returns a base64 encoded and with key encrypted pickled Decription using PickleLibOlm().
func (a Decription) Pickle(key []byte) ([]byte, error) {
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

// PickleLibOlm encodes the Decription into target. target has to have a size of at least PickleLen() and is written to from index 0.
// It returns the number of bytes written.
func (a Decription) PickleLibOlm(target []byte) (int, error) {
	if len(target) < a.PickleLen() {
		return 0, errors.Wrap(goolm.ErrValueTooShort, "pickle Decription")
	}
	written := libolmpickle.PickleUInt32(decryptionPickleVersionLibOlm, target)
	writtenKey, err := a.KeyPair.PickleLibOlm(target[written:])
	if err != nil {
		return 0, errors.Wrap(err, "pickle Decription")
	}
	written += writtenKey
	return written, nil
}

// PickleLen returns the number of bytes the pickled Decription will have.
func (a Decription) PickleLen() int {
	length := libolmpickle.PickleUInt32Len(decryptionPickleVersionLibOlm)
	length += a.KeyPair.PickleLen()
	return length
}
