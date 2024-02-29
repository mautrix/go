package pk

import (
	"crypto/rand"

	"github.com/element-hq/mautrix-go/crypto/goolm"
	"github.com/element-hq/mautrix-go/crypto/goolm/crypto"
	"github.com/element-hq/mautrix-go/id"
)

// Signing is used for signing a pk
type Signing struct {
	KeyPair crypto.Ed25519KeyPair `json:"key_pair"`
	Seed    []byte                `json:"seed"`
}

// NewSigningFromSeed constructs a new Signing based on a seed.
func NewSigningFromSeed(seed []byte) (*Signing, error) {
	s := &Signing{}
	s.Seed = seed
	s.KeyPair = crypto.Ed25519GenerateFromSeed(seed)
	return s, nil
}

// NewSigning returns a Signing based on a random seed
func NewSigning() (*Signing, error) {
	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	if err != nil {
		return nil, err
	}
	return NewSigningFromSeed(seed)
}

// Sign returns the signature of the message base64 encoded.
func (s Signing) Sign(message []byte) []byte {
	signature := s.KeyPair.Sign(message)
	return goolm.Base64Encode(signature)
}

// PublicKey returns the public key of the key pair base 64 encoded.
func (s Signing) PublicKey() id.Ed25519 {
	return s.KeyPair.B64Encoded()
}
