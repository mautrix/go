//go:build goolm

package olm

import (
	"encoding/json"

	"github.com/tidwall/sjson"

	"github.com/element-hq/mautrix-go/crypto/canonicaljson"
	"github.com/element-hq/mautrix-go/crypto/goolm/pk"
	"github.com/element-hq/mautrix-go/id"
)

// PkSigning stores a key pair for signing messages.
type PkSigning struct {
	pk.Signing
	PublicKey id.Ed25519
	Seed      []byte
}

// Clear clears the underlying memory of a PkSigning object.
func (p *PkSigning) Clear() {
	p.Signing = pk.Signing{}
}

// NewPkSigningFromSeed creates a new PkSigning object using the given seed.
func NewPkSigningFromSeed(seed []byte) (*PkSigning, error) {
	p := &PkSigning{}
	signing, err := pk.NewSigningFromSeed(seed)
	if err != nil {
		return nil, err
	}
	p.Signing = *signing
	p.Seed = seed
	p.PublicKey = p.Signing.PublicKey()
	return p, nil
}

// NewPkSigning creates a new PkSigning object, containing a key pair for signing messages.
func NewPkSigning() (*PkSigning, error) {
	p := &PkSigning{}
	signing, err := pk.NewSigning()
	if err != nil {
		return nil, err
	}
	p.Signing = *signing
	p.Seed = signing.Seed
	p.PublicKey = p.Signing.PublicKey()
	return p, err
}

// Sign creates a signature for the given message using this key.
func (p *PkSigning) Sign(message []byte) ([]byte, error) {
	return p.Signing.Sign(message), nil
}

// SignJSON creates a signature for the given object after encoding it to canonical JSON.
func (p *PkSigning) SignJSON(obj interface{}) (string, error) {
	objJSON, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	objJSON, _ = sjson.DeleteBytes(objJSON, "unsigned")
	objJSON, _ = sjson.DeleteBytes(objJSON, "signatures")
	signature, err := p.Sign(canonicaljson.CanonicalJSONAssumeValid(objJSON))
	if err != nil {
		return "", err
	}
	return string(signature), nil
}
