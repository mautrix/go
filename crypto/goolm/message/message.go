package message

import (
	"bytes"

	"maunium.net/go/mautrix/crypto/aessha2"
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
func (r *Message) EncodeAndMAC(cipher aessha2.AESSHA2) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte(r.Version)
	buf.Write(encodeVarInt(ratchetKeyTag))
	buf.Write(encodeVarString(r.RatchetKey))
	buf.Write(encodeVarInt(counterTag))
	buf.Write(encodeVarInt(r.Counter))
	buf.Write(encodeVarInt(cipherTextKeyTag))
	buf.Write(encodeVarString(r.Ciphertext))
	mac, err := cipher.MAC(buf.Bytes())
	return append(buf.Bytes(), mac[:countMACBytesMessage]...), err
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
