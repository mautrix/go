package message

import (
	"bytes"

	"github.com/element-hq/mautrix-go/crypto/goolm/cipher"
	"github.com/element-hq/mautrix-go/crypto/goolm/crypto"
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
func (r *GroupMessage) Decode(input []byte) error {
	r.Version = 0
	r.MessageIndex = 0
	r.Ciphertext = nil
	if len(input) == 0 {
		return nil
	}
	//first Byte is always version
	r.Version = input[0]
	curPos := 1
	for curPos < len(input)-countMACBytesGroupMessage-crypto.ED25519SignatureSize {
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
			case messageIndexTag:
				r.MessageIndex = value
				r.HasMessageIndex = true
			}
		} else if (curKey & 0b111) == 2 {
			//The value is of type string
			value, readBytes := decodeVarString(input[curPos:])
			if err := checkDecodeErr(readBytes); err != nil {
				return err
			}
			curPos += readBytes
			switch curKey {
			case cipherTextTag:
				r.Ciphertext = value
			}
		}
	}

	return nil
}

// EncodeAndMacAndSign encodes the message, creates the mac with the key and the cipher and signs the message.
// If macKey or cipher is nil, no mac is appended. If signKey is nil, no signature is appended.
func (r *GroupMessage) EncodeAndMacAndSign(macKey []byte, cipher cipher.Cipher, signKey *crypto.Ed25519KeyPair) ([]byte, error) {
	var lengthOfMessage int
	lengthOfMessage += 1 //Version
	lengthOfMessage += encodeVarIntByteLength(messageIndexTag) + encodeVarIntByteLength(r.MessageIndex)
	lengthOfMessage += encodeVarIntByteLength(cipherTextTag) + encodeVarStringByteLength(r.Ciphertext)
	out := make([]byte, lengthOfMessage)
	out[0] = r.Version
	curPos := 1
	encodedTag := encodeVarInt(messageIndexTag)
	copy(out[curPos:], encodedTag)
	curPos += len(encodedTag)
	encodedValue := encodeVarInt(r.MessageIndex)
	copy(out[curPos:], encodedValue)
	curPos += len(encodedValue)
	encodedTag = encodeVarInt(cipherTextTag)
	copy(out[curPos:], encodedTag)
	curPos += len(encodedTag)
	encodedValue = encodeVarString(r.Ciphertext)
	copy(out[curPos:], encodedValue)
	curPos += len(encodedValue)
	if len(macKey) != 0 && cipher != nil {
		mac, err := r.MAC(macKey, cipher, out)
		if err != nil {
			return nil, err
		}
		out = append(out, mac[:countMACBytesGroupMessage]...)
	}
	if signKey != nil {
		signature := signKey.Sign(out)
		out = append(out, signature...)
	}
	return out, nil
}

// MAC returns the MAC of the message calculated  with cipher and key. The length of the MAC is truncated to the correct length.
func (r *GroupMessage) MAC(key []byte, cipher cipher.Cipher, message []byte) ([]byte, error) {
	mac, err := cipher.MAC(key, message)
	if err != nil {
		return nil, err
	}
	return mac[:countMACBytesGroupMessage], nil
}

// VerifySignature verifies the givenSignature to the calculated signature of the message.
func (r *GroupMessage) VerifySignature(key crypto.Ed25519PublicKey, message, givenSignature []byte) bool {
	return key.Verify(message, givenSignature)
}

// VerifySignature verifies the signature taken from the message to the calculated signature of the message.
func (r *GroupMessage) VerifySignatureInline(key crypto.Ed25519PublicKey, message []byte) bool {
	signature := message[len(message)-crypto.ED25519SignatureSize:]
	message = message[:len(message)-crypto.ED25519SignatureSize]
	return key.Verify(message, signature)
}

// VerifyMAC verifies the givenMAC to the calculated MAC of the message.
func (r *GroupMessage) VerifyMAC(key []byte, cipher cipher.Cipher, message, givenMAC []byte) (bool, error) {
	checkMac, err := r.MAC(key, cipher, message)
	if err != nil {
		return false, err
	}
	return bytes.Equal(checkMac[:countMACBytesGroupMessage], givenMAC), nil
}

// VerifyMACInline verifies the MAC taken from the message to the calculated MAC of the message.
func (r *GroupMessage) VerifyMACInline(key []byte, cipher cipher.Cipher, message []byte) (bool, error) {
	startMAC := len(message) - countMACBytesGroupMessage - crypto.ED25519SignatureSize
	endMAC := startMAC + countMACBytesGroupMessage
	suplMac := message[startMAC:endMAC]
	message = message[:startMAC]
	return r.VerifyMAC(key, cipher, message, suplMac)
}
