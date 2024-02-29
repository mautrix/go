package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"

	"github.com/element-hq/mautrix-go/crypto/goolm"
	"github.com/element-hq/mautrix-go/crypto/goolm/libolmpickle"
	"github.com/element-hq/mautrix-go/id"
)

const (
	Curve25519KeyLength    = curve25519.ScalarSize //The length of the private key.
	curve25519PubKeyLength = 32
)

// Curve25519GenerateKey creates a new curve25519 key pair. If reader is nil, the random data is taken from crypto/rand.
func Curve25519GenerateKey(reader io.Reader) (Curve25519KeyPair, error) {
	privateKeyByte := make([]byte, Curve25519KeyLength)
	if reader == nil {
		_, err := rand.Read(privateKeyByte)
		if err != nil {
			return Curve25519KeyPair{}, err
		}
	} else {
		_, err := reader.Read(privateKeyByte)
		if err != nil {
			return Curve25519KeyPair{}, err
		}
	}

	privateKey := Curve25519PrivateKey(privateKeyByte)

	publicKey, err := privateKey.PubKey()
	if err != nil {
		return Curve25519KeyPair{}, err
	}
	return Curve25519KeyPair{
		PrivateKey: Curve25519PrivateKey(privateKey),
		PublicKey:  Curve25519PublicKey(publicKey),
	}, nil
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

// B64Encoded returns a base64 encoded string of the public key.
func (c Curve25519KeyPair) B64Encoded() id.Curve25519 {
	return c.PublicKey.B64Encoded()
}

// SharedSecret returns the shared secret between the key pair and the given public key.
func (c Curve25519KeyPair) SharedSecret(pubKey Curve25519PublicKey) ([]byte, error) {
	return c.PrivateKey.SharedSecret(pubKey)
}

// PickleLibOlm encodes the key pair into target. target has to have a size of at least PickleLen() and is written to from index 0.
// It returns the number of bytes written.
func (c Curve25519KeyPair) PickleLibOlm(target []byte) (int, error) {
	if len(target) < c.PickleLen() {
		return 0, fmt.Errorf("pickle curve25519 key pair: %w", goolm.ErrValueTooShort)
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

// PickleLen returns the number of bytes the pickled key pair will have.
func (c Curve25519KeyPair) PickleLen() int {
	lenPublic := c.PublicKey.PickleLen()
	var lenPrivate int
	if len(c.PrivateKey) != Curve25519KeyLength {
		lenPrivate = libolmpickle.PickleBytesLen(make([]byte, Curve25519KeyLength))
	} else {
		lenPrivate = libolmpickle.PickleBytesLen(c.PrivateKey)
	}
	return lenPublic + lenPrivate
}

// Curve25519PrivateKey represents the private key for curve25519 usage
type Curve25519PrivateKey []byte

// Equal compares the private key to the given private key.
func (c Curve25519PrivateKey) Equal(x Curve25519PrivateKey) bool {
	return bytes.Equal(c, x)
}

// PubKey returns the public key derived from the private key.
func (c Curve25519PrivateKey) PubKey() (Curve25519PublicKey, error) {
	publicKey, err := curve25519.X25519(c, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	return publicKey, nil
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
	if len(target) < c.PickleLen() {
		return 0, fmt.Errorf("pickle curve25519 public key: %w", goolm.ErrValueTooShort)
	}
	if len(c) != curve25519PubKeyLength {
		return libolmpickle.PickleBytes(make([]byte, curve25519PubKeyLength), target), nil
	}
	return libolmpickle.PickleBytes(c, target), nil
}

// UnpickleLibOlm decodes the unencryted value and populates the public key accordingly. It returns the number of bytes read.
func (c *Curve25519PublicKey) UnpickleLibOlm(value []byte) (int, error) {
	unpickled, readBytes, err := libolmpickle.UnpickleBytes(value, curve25519PubKeyLength)
	if err != nil {
		return 0, err
	}
	*c = unpickled
	return readBytes, nil
}

// PickleLen returns the number of bytes the pickled public key will have.
func (c Curve25519PublicKey) PickleLen() int {
	if len(c) != curve25519PubKeyLength {
		return libolmpickle.PickleBytesLen(make([]byte, curve25519PubKeyLength))
	}
	return libolmpickle.PickleBytesLen(c)
}
