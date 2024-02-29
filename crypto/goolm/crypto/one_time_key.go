package crypto

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/element-hq/mautrix-go/crypto/goolm"
	"github.com/element-hq/mautrix-go/crypto/goolm/libolmpickle"
	"github.com/element-hq/mautrix-go/id"
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

// PickleLibOlm encodes the key pair into target. target has to have a size of at least PickleLen() and is written to from index 0.
// It returns the number of bytes written.
func (c OneTimeKey) PickleLibOlm(target []byte) (int, error) {
	if len(target) < c.PickleLen() {
		return 0, fmt.Errorf("pickle one time key: %w", goolm.ErrValueTooShort)
	}
	written := libolmpickle.PickleUInt32(uint32(c.ID), target)
	written += libolmpickle.PickleBool(c.Published, target[written:])
	writtenKey, err := c.Key.PickleLibOlm(target[written:])
	if err != nil {
		return 0, fmt.Errorf("pickle one time key: %w", err)
	}
	written += writtenKey
	return written, nil
}

// UnpickleLibOlm decodes the unencryted value and populates the OneTimeKey accordingly. It returns the number of bytes read.
func (c *OneTimeKey) UnpickleLibOlm(value []byte) (int, error) {
	totalReadBytes := 0
	id, readBytes, err := libolmpickle.UnpickleUInt32(value)
	if err != nil {
		return 0, err
	}
	totalReadBytes += readBytes
	c.ID = id
	published, readBytes, err := libolmpickle.UnpickleBool(value[totalReadBytes:])
	if err != nil {
		return 0, err
	}
	totalReadBytes += readBytes
	c.Published = published
	readBytes, err = c.Key.UnpickleLibOlm(value[totalReadBytes:])
	if err != nil {
		return 0, err
	}
	totalReadBytes += readBytes
	return totalReadBytes, nil
}

// PickleLen returns the number of bytes the pickled OneTimeKey will have.
func (c OneTimeKey) PickleLen() int {
	length := 0
	length += libolmpickle.PickleUInt32Len(c.ID)
	length += libolmpickle.PickleBoolLen(c.Published)
	length += c.Key.PickleLen()
	return length
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
