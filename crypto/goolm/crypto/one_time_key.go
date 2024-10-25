package crypto

import (
	"encoding/base64"
	"encoding/binary"

	"maunium.net/go/mautrix/crypto/goolm/libolmpickle"
	"maunium.net/go/mautrix/id"
)

// OneTimeKey stores the information about a one time key.
type OneTimeKey struct {
	ID        uint32            `json:"id"`
	Published bool              `json:"published"`
	Key       Curve25519KeyPair `json:"key,omitempty"`
}

// Equal compares the one time key to the given one.
func (otk OneTimeKey) Equal(s OneTimeKey) bool {
	if otk.ID != s.ID {
		return false
	}
	if otk.Published != s.Published {
		return false
	}
	if !otk.Key.PrivateKey.Equal(s.Key.PrivateKey) {
		return false
	}
	if !otk.Key.PublicKey.Equal(s.Key.PublicKey) {
		return false
	}
	return true
}

// PickleLibOlm pickles the key pair into the encoder.
func (c OneTimeKey) PickleLibOlm(encoder *libolmpickle.Encoder) {
	encoder.WriteUInt32(c.ID)
	encoder.WriteBool(c.Published)
	c.Key.PickleLibOlm(encoder)
}

// UnpickleLibOlm unpickles the unencryted value and populates the [OneTimeKey]
// accordingly.
func (c *OneTimeKey) UnpickleLibOlm(decoder *libolmpickle.Decoder) (err error) {
	if c.ID, err = decoder.ReadUInt32(); err != nil {
		return
	} else if c.Published, err = decoder.ReadBool(); err != nil {
		return
	}
	return c.Key.UnpickleLibOlm(decoder)
}

// KeyIDEncoded returns the base64 encoded id.
func (c OneTimeKey) KeyIDEncoded() string {
	resSlice := make([]byte, 4)
	binary.BigEndian.PutUint32(resSlice, c.ID)
	return base64.RawStdEncoding.EncodeToString(resSlice)
}

// PublicKeyEncoded returns the base64 encoded public key
func (c OneTimeKey) PublicKeyEncoded() id.Curve25519 {
	return c.Key.PublicKey.B64Encoded()
}
