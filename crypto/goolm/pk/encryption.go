package pk

import (
	"encoding/base64"

	"maunium.net/go/mautrix/id"

	"maunium.net/go/mautrix/crypto/goolm/aessha2"
	"maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/crypto/goolm/goolmbase64"
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
	cipher, err := aessha2.NewAESSHA2(sharedSecret, nil)
	ciphertext, err = cipher.Encrypt(plaintext)
	if err != nil {
		return nil, nil, err
	}
	mac, err = cipher.MAC(ciphertext)
	return ciphertext, goolmbase64.Encode(mac), err
}
