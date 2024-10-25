package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"

	"maunium.net/go/mautrix/crypto/goolm/libolmpickle"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/id"
)

const (
	Curve25519KeyLength    = curve25519.ScalarSize //The length of the private key.
	Curve25519PubKeyLength = 32
)

// Curve25519GenerateKey creates a new curve25519 key pair.
func Curve25519GenerateKey() (Curve25519KeyPair, error) {
	privateKeyByte := make([]byte, Curve25519KeyLength)
	if _, err := rand.Read(privateKeyByte); err != nil {
		return Curve25519KeyPair{}, err
	}

	privateKey := Curve25519PrivateKey(privateKeyByte)
	publicKey, err := privateKey.PubKey()
	return Curve25519KeyPair{
		PrivateKey: Curve25519PrivateKey(privateKey),
		PublicKey:  Curve25519PublicKey(publicKey),
	}, err
}

// Curve25519GenerateFromPrivate creates a new curve25519 key pair with the private key given.
func Curve25519GenerateFromPrivate(private Curve25519PrivateKey) (Curve25519KeyPair, error) {
	publicKey, err := private.PubKey()
	if err != nil {
		return Curve25519KeyPair{}, err
	}
	return Curve25519KeyPair{
		PrivateKey: private,
		PublicKey:  Curve25519PublicKey(publicKey),
	}, nil
}

// Curve25519KeyPair stores both parts of a curve25519 key.
type Curve25519KeyPair struct {
	PrivateKey Curve25519PrivateKey `json:"private,omitempty"`
	PublicKey  Curve25519PublicKey  `json:"public,omitempty"`
}

const Curve25519KeyPairPickleLength = Curve25519PubKeyLength + // Public Key
	Curve25519KeyLength // Private Key

// B64Encoded returns a base64 encoded string of the public key.
func (c Curve25519KeyPair) B64Encoded() id.Curve25519 {
	return c.PublicKey.B64Encoded()
}

// SharedSecret returns the shared secret between the key pair and the given public key.
func (c Curve25519KeyPair) SharedSecret(pubKey Curve25519PublicKey) ([]byte, error) {
	return c.PrivateKey.SharedSecret(pubKey)
}

// PickleLibOlm encodes the key pair into target. The target has to have a size
// of at least [Curve25519KeyPairPickleLength] and is written to from index 0.
// It returns the number of bytes written.
func (c Curve25519KeyPair) PickleLibOlm(target []byte) (int, error) {
	if len(target) < Curve25519KeyPairPickleLength {
		return 0, fmt.Errorf("pickle curve25519 key pair: %w", olm.ErrValueTooShort)
	}
	written, err := c.PublicKey.PickleLibOlm(target)
	if err != nil {
		return 0, fmt.Errorf("pickle curve25519 key pair: %w", err)
	}
	if len(c.PrivateKey) != Curve25519KeyLength {
		written += libolmpickle.PickleBytes(make([]byte, Curve25519KeyLength), target[written:])
	} else {
		written += libolmpickle.PickleBytes(c.PrivateKey, target[written:])
	}
	return written, nil
}

// UnpickleLibOlm decodes the unencryted value and populates the key pair accordingly. It returns the number of bytes read.
func (c *Curve25519KeyPair) UnpickleLibOlm(value []byte) (int, error) {
	//unpickle PubKey
	read, err := c.PublicKey.UnpickleLibOlm(value)
	if err != nil {
		return 0, err
	}
	//unpickle PrivateKey
	privKey, readPriv, err := libolmpickle.UnpickleBytes(value[read:], Curve25519KeyLength)
	if err != nil {
		return read, err
	}
	c.PrivateKey = privKey
	return read + readPriv, nil
}

// Curve25519PrivateKey represents the private key for curve25519 usage
type Curve25519PrivateKey []byte

// Equal compares the private key to the given private key.
func (c Curve25519PrivateKey) Equal(x Curve25519PrivateKey) bool {
	return bytes.Equal(c, x)
}

// PubKey returns the public key derived from the private key.
func (c Curve25519PrivateKey) PubKey() (Curve25519PublicKey, error) {
	return curve25519.X25519(c, curve25519.Basepoint)
}

// SharedSecret returns the shared secret between the private key and the given public key.
func (c Curve25519PrivateKey) SharedSecret(pubKey Curve25519PublicKey) ([]byte, error) {
	return curve25519.X25519(c, pubKey)
}

// Curve25519PublicKey represents the public key for curve25519 usage
type Curve25519PublicKey []byte

// Equal compares the public key to the given public key.
func (c Curve25519PublicKey) Equal(x Curve25519PublicKey) bool {
	return bytes.Equal(c, x)
}

// B64Encoded returns a base64 encoded string of the public key.
func (c Curve25519PublicKey) B64Encoded() id.Curve25519 {
	return id.Curve25519(base64.RawStdEncoding.EncodeToString(c))
}

// PickleLibOlm encodes the public key into target. target has to have a size of at least PickleLen() and is written to from index 0.
// It returns the number of bytes written.
func (c Curve25519PublicKey) PickleLibOlm(target []byte) (int, error) {
	if len(target) < Curve25519PubKeyLength {
		return 0, fmt.Errorf("pickle curve25519 public key: %w", olm.ErrValueTooShort)
	}
	if len(c) != Curve25519PubKeyLength {
		return libolmpickle.PickleBytes(make([]byte, Curve25519PubKeyLength), target), nil
	}
	return libolmpickle.PickleBytes(c, target), nil
}

// UnpickleLibOlm decodes the unencryted value and populates the public key accordingly. It returns the number of bytes read.
func (c *Curve25519PublicKey) UnpickleLibOlm(value []byte) (int, error) {
	unpickled, readBytes, err := libolmpickle.UnpickleBytes(value, Curve25519PubKeyLength)
	if err != nil {
		return 0, err
	}
	*c = unpickled
	return readBytes, nil
}
