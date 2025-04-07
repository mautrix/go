package message

import (
	"bytes"
	"io"

	"maunium.net/go/mautrix/crypto/goolm/aessha2"
	"maunium.net/go/mautrix/crypto/goolm/crypto"
)

const (
	ratchetKeyTag        = 0x0A
	counterTag           = 0x10
	cipherTextKeyTag     = 0x22
	countMACBytesMessage = 8
)

// GroupMessage represents a message in the message format.
type Message struct {
	Version    byte                       `json:"version"`
	HasCounter bool                       `json:"has_counter"`
	Counter    uint32                     `json:"counter"`
	RatchetKey crypto.Curve25519PublicKey `json:"ratchet_key"`
	Ciphertext []byte                     `json:"ciphertext"`
}

// Decodes decodes the input and populates the corresponding fileds. MAC is ignored but has to be present.
func (r *Message) Decode(input []byte) (err error) {
	r.Version = 0
	r.HasCounter = false
	r.Counter = 0
	r.RatchetKey = nil
	r.Ciphertext = nil
	if len(input) == 0 {
		return nil
	}

	decoder := NewDecoder(input[:len(input)-countMACBytesMessage])
	r.Version, err = decoder.ReadByte() // first byte is always version
	if err != nil {
		return
	}

	for {
		// Read Key
		if curKey, err := decoder.ReadVarInt(); err != nil {
			if err == io.EOF {
				// No more keys to read
				return nil
			}
			return err
		} else if (curKey & 0b111) == 0 {
			// The value is of type varint
			if value, err := decoder.ReadVarInt(); err != nil {
				return err
			} else if curKey == counterTag {
				r.Counter = uint32(value)
				r.HasCounter = true
			}
		} else if (curKey & 0b111) == 2 {
			// The value is of type string
			if value, err := decoder.ReadVarBytes(); err != nil {
				return err
			} else if curKey == ratchetKeyTag {
				r.RatchetKey = value
			} else if curKey == cipherTextKeyTag {
				r.Ciphertext = value
			}
		}
	}
}

// EncodeAndMAC encodes the message and creates the MAC with the key and the cipher.
// If key or cipher is nil, no MAC is appended.
func (r *Message) EncodeAndMAC(cipher aessha2.AESSHA2) ([]byte, error) {
	var encoder Encoder
	encoder.PutByte(r.Version)
	encoder.PutVarInt(ratchetKeyTag)
	encoder.PutVarBytes(r.RatchetKey)
	encoder.PutVarInt(counterTag)
	encoder.PutVarInt(uint64(r.Counter))
	encoder.PutVarInt(cipherTextKeyTag)
	encoder.PutVarBytes(r.Ciphertext)
	mac, err := cipher.MAC(encoder.Bytes())
	return append(encoder.Bytes(), mac[:countMACBytesMessage]...), err
}

// VerifyMAC verifies the givenMAC to the calculated MAC of the message.
func (r *Message) VerifyMAC(key []byte, cipher aessha2.AESSHA2, ciphertext, givenMAC []byte) (bool, error) {
	checkMAC, err := cipher.MAC(ciphertext)
	if err != nil {
		return false, err
	}
	return bytes.Equal(checkMAC[:countMACBytesMessage], givenMAC), nil
}

// VerifyMACInline verifies the MAC taken from the message to the calculated MAC of the message.
func (r *Message) VerifyMACInline(key []byte, cipher aessha2.AESSHA2, message []byte) (bool, error) {
	givenMAC := message[len(message)-countMACBytesMessage:]
	return r.VerifyMAC(key, cipher, message[:len(message)-countMACBytesMessage], givenMAC)
}
