package message

import (
	"bytes"

	"maunium.net/go/mautrix/crypto/aessha2"
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
	for curPos < len(input)-countMACBytesGroupMessage-crypto.Ed25519SignatureSize {
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

// EncodeAndMACAndSign encodes the message, creates the mac with the key and the cipher and signs the message.
// If macKey or cipher is nil, no mac is appended. If signKey is nil, no signature is appended.
func (r *GroupMessage) EncodeAndMACAndSign(cipher aessha2.AESSHA2, signKey crypto.Ed25519KeyPair) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte(r.Version)
	buf.Write(encodeVarInt(messageIndexTag))
	buf.Write(encodeVarInt(r.MessageIndex))
	buf.Write(encodeVarInt(cipherTextTag))
	buf.Write(encodeVarString(r.Ciphertext))
	mac, err := r.MAC(cipher, buf.Bytes())
	if err != nil {
		return nil, err
	}
	ciphertextWithMAC := append(buf.Bytes(), mac[:countMACBytesGroupMessage]...)
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
