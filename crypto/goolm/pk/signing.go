package pk

import (
	"crypto/rand"
	"encoding/json"

	"github.com/tidwall/sjson"

	"maunium.net/go/mautrix/crypto/canonicaljson"
	"maunium.net/go/mautrix/crypto/goolm"
	"maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/id"
)

// Signing is used for signing a pk
type Signing struct {
	keyPair crypto.Ed25519KeyPair
	seed    []byte
}

// NewSigningFromSeed constructs a new Signing based on a seed.
func NewSigningFromSeed(seed []byte) (*Signing, error) {
	s := &Signing{}
	s.seed = seed
	s.keyPair = crypto.Ed25519GenerateFromSeed(seed)
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

// Seed returns the seed of the key pair.
func (s Signing) Seed() []byte {
	return s.seed
}

// PublicKey returns the public key of the key pair base 64 encoded.
func (s Signing) PublicKey() id.Ed25519 {
	return s.keyPair.B64Encoded()
}

// Sign returns the signature of the message base64 encoded.
func (s Signing) Sign(message []byte) ([]byte, error) {
	signature := s.keyPair.Sign(message)
	return goolm.Base64Encode(signature), nil
}

// SignJSON creates a signature for the given object after encoding it to
// canonical JSON.
func (s Signing) SignJSON(obj any) (string, error) {
	objJSON, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	objJSON, _ = sjson.DeleteBytes(objJSON, "unsigned")
	objJSON, _ = sjson.DeleteBytes(objJSON, "signatures")
	signature, err := s.Sign(canonicaljson.CanonicalJSONAssumeValid(objJSON))
	if err != nil {
		return "", err
	}
	return string(signature), nil
}
