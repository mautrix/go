package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/element-hq/mautrix-go/crypto/goolm"
	"github.com/element-hq/mautrix-go/crypto/goolm/libolmpickle"
	"github.com/element-hq/mautrix-go/id"
)

const (
	ED25519SignatureSize = ed25519.SignatureSize //The length of a signature
)

// Ed25519GenerateKey creates a new ed25519 key pair. If reader is nil, the random data is taken from crypto/rand.
func Ed25519GenerateKey(reader io.Reader) (Ed25519KeyPair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(reader)
	if err != nil {
		return Ed25519KeyPair{}, err
	}
	return Ed25519KeyPair{
		PrivateKey: Ed25519PrivateKey(privateKey),
		PublicKey:  Ed25519PublicKey(publicKey),
	}, nil
}

// Ed25519GenerateFromPrivate creates a new ed25519 key pair with the private key given.
func Ed25519GenerateFromPrivate(privKey Ed25519PrivateKey) Ed25519KeyPair {
	return Ed25519KeyPair{
		PrivateKey: privKey,
		PublicKey:  privKey.PubKey(),
	}
}

// Ed25519GenerateFromSeed creates a new ed25519 key pair with a given seed.
func Ed25519GenerateFromSeed(seed []byte) Ed25519KeyPair {
	privKey := Ed25519PrivateKey(ed25519.NewKeyFromSeed(seed))
	return Ed25519KeyPair{
		PrivateKey: privKey,
		PublicKey:  privKey.PubKey(),
	}
}

// Ed25519KeyPair stores both parts of a ed25519 key.
type Ed25519KeyPair struct {
	PrivateKey Ed25519PrivateKey `json:"private,omitempty"`
	PublicKey  Ed25519PublicKey  `json:"public,omitempty"`
}

// B64Encoded returns a base64 encoded string of the public key.
func (c Ed25519KeyPair) B64Encoded() id.Ed25519 {
	return id.Ed25519(base64.RawStdEncoding.EncodeToString(c.PublicKey))
}

// Sign returns the signature for the message.
func (c Ed25519KeyPair) Sign(message []byte) []byte {
	return c.PrivateKey.Sign(message)
}

// Verify checks the signature of the message against the givenSignature
func (c Ed25519KeyPair) Verify(message, givenSignature []byte) bool {
	return c.PublicKey.Verify(message, givenSignature)
}

// PickleLibOlm encodes the key pair into target. target has to have a size of at least PickleLen() and is written to from index 0.
// It returns the number of bytes written.
func (c Ed25519KeyPair) PickleLibOlm(target []byte) (int, error) {
	if len(target) < c.PickleLen() {
		return 0, fmt.Errorf("pickle ed25519 key pair: %w", goolm.ErrValueTooShort)
	}
	written, err := c.PublicKey.PickleLibOlm(target)
	if err != nil {
		return 0, fmt.Errorf("pickle ed25519 key pair: %w", err)
	}

	if len(c.PrivateKey) != ed25519.PrivateKeySize {
		written += libolmpickle.PickleBytes(make([]byte, ed25519.PrivateKeySize), target[written:])
	} else {
		written += libolmpickle.PickleBytes(c.PrivateKey, target[written:])
	}
	return written, nil
}

// UnpickleLibOlm decodes the unencryted value and populates the key pair accordingly. It returns the number of bytes read.
func (c *Ed25519KeyPair) UnpickleLibOlm(value []byte) (int, error) {
	//unpickle PubKey
	read, err := c.PublicKey.UnpickleLibOlm(value)
	if err != nil {
		return 0, err
	}
	//unpickle PrivateKey
	privKey, readPriv, err := libolmpickle.UnpickleBytes(value[read:], ed25519.PrivateKeySize)
	if err != nil {
		return read, err
	}
	c.PrivateKey = privKey
	return read + readPriv, nil
}

// PickleLen returns the number of bytes the pickled key pair will have.
func (c Ed25519KeyPair) PickleLen() int {
	lenPublic := c.PublicKey.PickleLen()
	var lenPrivate int
	if len(c.PrivateKey) != ed25519.PrivateKeySize {
		lenPrivate = libolmpickle.PickleBytesLen(make([]byte, ed25519.PrivateKeySize))
	} else {
		lenPrivate = libolmpickle.PickleBytesLen(c.PrivateKey)
	}
	return lenPublic + lenPrivate
}

// Curve25519PrivateKey represents the private key for ed25519 usage. This is just a wrapper.
type Ed25519PrivateKey ed25519.PrivateKey

// Equal compares the private key to the given private key.
func (c Ed25519PrivateKey) Equal(x Ed25519PrivateKey) bool {
	return bytes.Equal(c, x)
}

// PubKey returns the public key derived from the private key.
func (c Ed25519PrivateKey) PubKey() Ed25519PublicKey {
	publicKey := ed25519.PrivateKey(c).Public()
	return Ed25519PublicKey(publicKey.(ed25519.PublicKey))
}

// Sign returns the signature for the message.
func (c Ed25519PrivateKey) Sign(message []byte) []byte {
	return ed25519.Sign(ed25519.PrivateKey(c), message)
}

// Ed25519PublicKey represents the public key for ed25519 usage. This is just a wrapper.
type Ed25519PublicKey ed25519.PublicKey

// Equal compares the public key to the given public key.
func (c Ed25519PublicKey) Equal(x Ed25519PublicKey) bool {
	return bytes.Equal(c, x)
}

// B64Encoded returns a base64 encoded string of the public key.
func (c Ed25519PublicKey) B64Encoded() id.Curve25519 {
	return id.Curve25519(base64.RawStdEncoding.EncodeToString(c))
}

// Verify checks the signature of the message against the givenSignature
func (c Ed25519PublicKey) Verify(message, givenSignature []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(c), message, givenSignature)
}

// PickleLibOlm encodes the public key into target. target has to have a size of at least PickleLen() and is written to from index 0.
// It returns the number of bytes written.
func (c Ed25519PublicKey) PickleLibOlm(target []byte) (int, error) {
	if len(target) < c.PickleLen() {
		return 0, fmt.Errorf("pickle ed25519 public key: %w", goolm.ErrValueTooShort)
	}
	if len(c) != ed25519.PublicKeySize {
		return libolmpickle.PickleBytes(make([]byte, ed25519.PublicKeySize), target), nil
	}
	return libolmpickle.PickleBytes(c, target), nil
}

// UnpickleLibOlm decodes the unencryted value and populates the public key accordingly. It returns the number of bytes read.
func (c *Ed25519PublicKey) UnpickleLibOlm(value []byte) (int, error) {
	unpickled, readBytes, err := libolmpickle.UnpickleBytes(value, ed25519.PublicKeySize)
	if err != nil {
		return 0, err
	}
	*c = unpickled
	return readBytes, nil
}

// PickleLen returns the number of bytes the pickled public key will have.
func (c Ed25519PublicKey) PickleLen() int {
	if len(c) != ed25519.PublicKeySize {
		return libolmpickle.PickleBytesLen(make([]byte, ed25519.PublicKeySize))
	}
	return libolmpickle.PickleBytesLen(c)
}
