// sas provides the means to do SAS between keys
package sas

import (
	"io"

	"github.com/element-hq/mautrix-go/crypto/goolm"
	"github.com/element-hq/mautrix-go/crypto/goolm/crypto"
)

// SAS contains the key pair and secret for SAS.
type SAS struct {
	KeyPair crypto.Curve25519KeyPair
	Secret  []byte
}

// New creates a new SAS with a new key pair.
func New() (*SAS, error) {
	kp, err := crypto.Curve25519GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	s := &SAS{
		KeyPair: kp,
	}
	return s, nil
}

// GetPubkey returns the public key of the key pair base64 encoded
func (s SAS) GetPubkey() []byte {
	return goolm.Base64Encode(s.KeyPair.PublicKey)
}

// SetTheirKey sets the key of the other party and computes the shared secret.
func (s *SAS) SetTheirKey(key []byte) error {
	keyDecoded, err := goolm.Base64Decode(key)
	if err != nil {
		return err
	}
	sharedSecret, err := s.KeyPair.SharedSecret(keyDecoded)
	if err != nil {
		return err
	}
	s.Secret = sharedSecret
	return nil
}

// GenerateBytes creates length bytes from the shared secret and info.
func (s SAS) GenerateBytes(info []byte, length uint) ([]byte, error) {
	byteReader := crypto.HKDFSHA256(s.Secret, nil, info)
	output := make([]byte, length)
	if _, err := io.ReadFull(byteReader, output); err != nil {
		return nil, err
	}
	return output, nil
}

// calculateMAC returns a base64 encoded MAC of input.
func (s *SAS) calculateMAC(input, info []byte, length uint) ([]byte, error) {
	key, err := s.GenerateBytes(info, length)
	if err != nil {
		return nil, err
	}
	mac := crypto.HMACSHA256(key, input)
	return goolm.Base64Encode(mac), nil
}

// CalculateMACFixes returns a base64 encoded, 32 byte long MAC of input.
func (s SAS) CalculateMAC(input, info []byte) ([]byte, error) {
	return s.calculateMAC(input, info, 32)
}

// CalculateMACLongKDF returns a base64 encoded, 256 byte long MAC of input.
func (s SAS) CalculateMACLongKDF(input, info []byte) ([]byte, error) {
	return s.calculateMAC(input, info, 256)
}
