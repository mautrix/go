package pk

import (
	"encoding/base64"
	"fmt"

	"maunium.net/go/mautrix/crypto/goolm/aessha2"
	"maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/crypto/goolm/goolmbase64"
	"maunium.net/go/mautrix/crypto/goolm/libolmpickle"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/id"
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
	keyPair, err := crypto.Curve25519GenerateKey()
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

// PublicKey returns the public key base 64 encoded.
func (s Decryption) PublicKey() id.Curve25519 {
	return s.KeyPair.B64Encoded()
}

// PrivateKey returns the private key.
func (s Decryption) PrivateKey() crypto.Curve25519PrivateKey {
	return s.KeyPair.PrivateKey
}

// Decrypt decrypts the ciphertext and verifies the MAC. The base64 encoded key is used to construct the shared secret.
func (s Decryption) Decrypt(ephemeralKey, mac, ciphertext []byte) ([]byte, error) {
	if keyDecoded, err := base64.RawStdEncoding.DecodeString(string(ephemeralKey)); err != nil {
		return nil, err
	} else if sharedSecret, err := s.KeyPair.SharedSecret(keyDecoded); err != nil {
		return nil, err
	} else if decodedMAC, err := goolmbase64.Decode(mac); err != nil {
		return nil, err
	} else if cipher, err := aessha2.NewAESSHA2(sharedSecret, nil); err != nil {
		return nil, err
	} else if verified, err := cipher.VerifyMAC(ciphertext, decodedMAC); err != nil {
		return nil, err
	} else if !verified {
		return nil, fmt.Errorf("decrypt: %w", olm.ErrBadMAC)
	} else {
		return cipher.Decrypt(ciphertext)
	}
}

// PickleAsJSON returns an Decryption as a base64 string encrypted using the supplied key. The unencrypted representation of the Account is in JSON format.
func (a Decryption) PickleAsJSON(key []byte) ([]byte, error) {
	return libolmpickle.PickleAsJSON(a, decryptionPickleVersionJSON, key)
}

// UnpickleAsJSON updates an Decryption by a base64 encrypted string using the supplied key. The unencrypted representation has to be in JSON format.
func (a *Decryption) UnpickleAsJSON(pickled, key []byte) error {
	return libolmpickle.UnpickleAsJSON(a, pickled, key, decryptionPickleVersionJSON)
}

// Unpickle decodes the base64 encoded string and decrypts the result with the key.
// The decrypted value is then passed to UnpickleLibOlm.
func (a *Decryption) Unpickle(pickled, key []byte) error {
	decrypted, err := libolmpickle.Unpickle(key, pickled)
	if err != nil {
		return err
	}
	return a.UnpickleLibOlm(decrypted)
}

// UnpickleLibOlm decodes the unencryted value and populates the Decryption accordingly. It returns the number of bytes read.
func (a *Decryption) UnpickleLibOlm(unpickled []byte) error {
	decoder := libolmpickle.NewDecoder(unpickled)
	pickledVersion, err := decoder.ReadUInt32()
	if err != nil {
		return err
	}
	if pickledVersion == decryptionPickleVersionLibOlm {
		return a.KeyPair.UnpickleLibOlm(decoder)
	} else {
		return fmt.Errorf("unpickle olmSession: %w (found %d, expected %d)", olm.ErrBadVersion, pickledVersion, decryptionPickleVersionLibOlm)
	}
}

// Pickle returns a base64 encoded and with key encrypted pickled Decryption using PickleLibOlm().
func (a Decryption) Pickle(key []byte) ([]byte, error) {
	return libolmpickle.Pickle(key, a.PickleLibOlm())
}

// PickleLibOlm pickles the [Decryption] into the encoder.
func (a Decryption) PickleLibOlm() []byte {
	encoder := libolmpickle.NewEncoder()
	encoder.WriteUInt32(decryptionPickleVersionLibOlm)
	a.KeyPair.PickleLibOlm(encoder)
	return encoder.Bytes()
}
