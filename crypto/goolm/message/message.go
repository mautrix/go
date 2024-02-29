package message

import (
	"bytes"

	"github.com/element-hq/mautrix-go/crypto/goolm/cipher"
	"github.com/element-hq/mautrix-go/crypto/goolm/crypto"
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
func (r *Message) Decode(input []byte) error {
	r.Version = 0
	r.HasCounter = false
	r.Counter = 0
	r.RatchetKey = nil
	r.Ciphertext = nil
	if len(input) == 0 {
		return nil
	}
	//first Byte is always version
	r.Version = input[0]
	curPos := 1
	for curPos < len(input)-countMACBytesMessage {
		//Read Key
		curKey, readBytes := decodeVarInt(input[curPos:])
		if err := checkDecodeErr(readBytes); err != nil {
			return err
		}
		curPos += readBytes
		if (curKey & 0b111) == 0 {
			//The value is of type varint
			value, readBytes := decodeVarInt(input[curPos:])
			if err := checkDecodeErr(readBytes); err != nil {
				return err
			}
			curPos += readBytes
			switch curKey {
			case counterTag:
				r.HasCounter = true
				r.Counter = value
			}
		} else if (curKey & 0b111) == 2 {
			//The value is of type string
			value, readBytes := decodeVarString(input[curPos:])
			if err := checkDecodeErr(readBytes); err != nil {
				return err
			}
			curPos += readBytes
			switch curKey {
			case ratchetKeyTag:
				r.RatchetKey = value
			case cipherTextKeyTag:
				r.Ciphertext = value
			}
		}
	}

	return nil
}

// EncodeAndMAC encodes the message and creates the MAC with the key and the cipher.
// If key or cipher is nil, no MAC is appended.
func (r *Message) EncodeAndMAC(key []byte, cipher cipher.Cipher) ([]byte, error) {
	var lengthOfMessage int
	lengthOfMessage += 1 //Version
	lengthOfMessage += encodeVarIntByteLength(ratchetKeyTag) + encodeVarStringByteLength(r.RatchetKey)
	lengthOfMessage += encodeVarIntByteLength(counterTag) + encodeVarIntByteLength(r.Counter)
	lengthOfMessage += encodeVarIntByteLength(cipherTextKeyTag) + encodeVarStringByteLength(r.Ciphertext)
	out := make([]byte, lengthOfMessage)
	out[0] = r.Version
	curPos := 1
	encodedTag := encodeVarInt(ratchetKeyTag)
	copy(out[curPos:], encodedTag)
	curPos += len(encodedTag)
	encodedValue := encodeVarString(r.RatchetKey)
	copy(out[curPos:], encodedValue)
	curPos += len(encodedValue)
	encodedTag = encodeVarInt(counterTag)
	copy(out[curPos:], encodedTag)
	curPos += len(encodedTag)
	encodedValue = encodeVarInt(r.Counter)
	copy(out[curPos:], encodedValue)
	curPos += len(encodedValue)
	encodedTag = encodeVarInt(cipherTextKeyTag)
	copy(out[curPos:], encodedTag)
	curPos += len(encodedTag)
	encodedValue = encodeVarString(r.Ciphertext)
	copy(out[curPos:], encodedValue)
	curPos += len(encodedValue)
	if len(key) != 0 && cipher != nil {
		mac, err := cipher.MAC(key, out)
		if err != nil {
			return nil, err
		}
		out = append(out, mac[:countMACBytesMessage]...)
	}
	return out, nil
}

// VerifyMAC verifies the givenMAC to the calculated MAC of the message.
func (r *Message) VerifyMAC(key []byte, cipher cipher.Cipher, message, givenMAC []byte) (bool, error) {
	checkMAC, err := cipher.MAC(key, message)
	if err != nil {
		return false, err
	}
	return bytes.Equal(checkMAC[:countMACBytesMessage], givenMAC), nil
}

// VerifyMACInline verifies the MAC taken from the message to the calculated MAC of the message.
func (r *Message) VerifyMACInline(key []byte, cipher cipher.Cipher, message []byte) (bool, error) {
	givenMAC := message[len(message)-countMACBytesMessage:]
	return r.VerifyMAC(key, cipher, message[:len(message)-countMACBytesMessage], givenMAC)
}
