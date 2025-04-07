package message

import (
	"bytes"
	"io"

	"maunium.net/go/mautrix/crypto/goolm/aessha2"
	"maunium.net/go/mautrix/crypto/goolm/crypto"
)

const (
	messageIndexTag           = 0x08
	cipherTextTag             = 0x12
	countMACBytesGroupMessage = 8
)

// GroupMessage represents a message in the group message format.
type GroupMessage struct {
	Version         byte   `json:"version"`
	MessageIndex    uint32 `json:"index"`
	Ciphertext      []byte `json:"ciphertext"`
	HasMessageIndex bool   `json:"has_index"`
}

// Decodes decodes the input and populates the corresponding fileds. MAC and signature are ignored but have to be present.
func (r *GroupMessage) Decode(input []byte) (err error) {
	r.Version = 0
	r.MessageIndex = 0
	r.Ciphertext = nil
	if len(input) == 0 {
		return nil
	}

	decoder := NewDecoder(input[:len(input)-countMACBytesGroupMessage-crypto.Ed25519SignatureSize])
	r.Version, err = decoder.ReadByte() // First byte is the version
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
			} else if curKey == messageIndexTag {
				r.MessageIndex = uint32(value)
				r.HasMessageIndex = true
			}
		} else if (curKey & 0b111) == 2 {
			// The value is of type string
			if value, err := decoder.ReadVarBytes(); err != nil {
				return err
			} else if curKey == cipherTextTag {
				r.Ciphertext = value
			}
		}
	}
}

// EncodeAndMACAndSign encodes the message, creates the mac with the key and the cipher and signs the message.
// If macKey or cipher is nil, no mac is appended. If signKey is nil, no signature is appended.
func (r *GroupMessage) EncodeAndMACAndSign(cipher aessha2.AESSHA2, signKey crypto.Ed25519KeyPair) ([]byte, error) {
	var encoder Encoder
	encoder.PutByte(r.Version)
	encoder.PutVarInt(messageIndexTag)
	encoder.PutVarInt(uint64(r.MessageIndex))
	encoder.PutVarInt(cipherTextTag)
	encoder.PutVarBytes(r.Ciphertext)
	mac, err := r.MAC(cipher, encoder.Bytes())
	if err != nil {
		return nil, err
	}
	ciphertextWithMAC := append(encoder.Bytes(), mac[:countMACBytesGroupMessage]...)
	signature, err := signKey.Sign(ciphertextWithMAC)
	return append(ciphertextWithMAC, signature...), err
}

// MAC returns the MAC of the message calculated  with cipher and key. The length of the MAC is truncated to the correct length.
func (r *GroupMessage) MAC(cipher aessha2.AESSHA2, ciphertext []byte) ([]byte, error) {
	mac, err := cipher.MAC(ciphertext)
	if err != nil {
		return nil, err
	}
	return mac[:countMACBytesGroupMessage], nil
}

// VerifySignature verifies the signature taken from the message to the calculated signature of the message.
func (r *GroupMessage) VerifySignatureInline(key crypto.Ed25519PublicKey, message []byte) bool {
	signature := message[len(message)-crypto.Ed25519SignatureSize:]
	message = message[:len(message)-crypto.Ed25519SignatureSize]
	return key.Verify(message, signature)
}

// VerifyMAC verifies the givenMAC to the calculated MAC of the message.
func (r *GroupMessage) VerifyMAC(cipher aessha2.AESSHA2, ciphertext, givenMAC []byte) (bool, error) {
	checkMac, err := r.MAC(cipher, ciphertext)
	if err != nil {
		return false, err
	}
	return bytes.Equal(checkMac[:countMACBytesGroupMessage], givenMAC), nil
}

// VerifyMACInline verifies the MAC taken from the message to the calculated MAC of the message.
func (r *GroupMessage) VerifyMACInline(cipher aessha2.AESSHA2, message []byte) (bool, error) {
	startMAC := len(message) - countMACBytesGroupMessage - crypto.Ed25519SignatureSize
	endMAC := startMAC + countMACBytesGroupMessage
	suplMac := message[startMAC:endMAC]
	message = message[:startMAC]
	return r.VerifyMAC(cipher, message, suplMac)
}
