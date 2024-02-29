package pk

import (
	"encoding/base64"

	"github.com/element-hq/mautrix-go/id"

	"github.com/element-hq/mautrix-go/crypto/goolm"
	"github.com/element-hq/mautrix-go/crypto/goolm/cipher"
	"github.com/element-hq/mautrix-go/crypto/goolm/crypto"
)

// Encryption is used to encrypt pk messages
type Encryption struct {
	RecipientKey crypto.Curve25519PublicKey `json:"recipient_key"`
}

// NewEncryption returns a new Encryption with the base64 encoded public key of the recipient
func NewEncryption(pubKey id.Curve25519) (*Encryption, error) {
	pubKeyDecoded, err := base64.RawStdEncoding.DecodeString(string(pubKey))
	if err != nil {
		return nil, err
	}
	return &Encryption{
		RecipientKey: pubKeyDecoded,
	}, nil
}

// Encrypt encrypts the plaintext with the privateKey and returns the ciphertext and base64 encoded MAC.
func (e Encryption) Encrypt(plaintext []byte, privateKey crypto.Curve25519PrivateKey) (ciphertext, mac []byte, err error) {
	keyPair, err := crypto.Curve25519GenerateFromPrivate(privateKey)
	if err != nil {
		return nil, nil, err
	}
	sharedSecret, err := keyPair.SharedSecret(e.RecipientKey)
	if err != nil {
		return nil, nil, err
	}
	cipher := cipher.NewAESSHA256(nil)
	ciphertext, err = cipher.Encrypt(sharedSecret, plaintext)
	if err != nil {
		return nil, nil, err
	}
	mac, err = cipher.MAC(sharedSecret, ciphertext)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, goolm.Base64Encode(mac), nil
}
