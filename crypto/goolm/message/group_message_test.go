package message_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/crypto/goolm/aessha2"
	"maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/crypto/goolm/message"
)

func TestGroupMessageDecode(t *testing.T) {
	messageRaw := []byte("\x03\x08\xC8\x01\x12\x0aciphertexthmacsha2")
	signature := []byte("signature1234567891234567890123412345678912345678912345678901234")
	messageRaw = append(messageRaw, signature...)
	expectedMessageIndex := uint32(200)
	expectedCipherText := []byte("ciphertext")

	msg := message.GroupMessage{}
	err := msg.Decode(messageRaw)
	assert.NoError(t, err)
	assert.EqualValues(t, 3, msg.Version)
	assert.Equal(t, expectedMessageIndex, msg.MessageIndex)
	assert.Equal(t, expectedCipherText, msg.Ciphertext)
}

func TestGroupMessageEncode(t *testing.T) {
	hmacsha256 := []byte("hmacsha2")
	sign := []byte("signature")
	msg := message.GroupMessage{
		Version:      3,
		MessageIndex: 200,
		Ciphertext:   []byte("ciphertext"),
	}

	cipher, err := aessha2.NewAESSHA2(nil, nil)
	require.NoError(t, err)
	encoded, err := msg.EncodeAndMACAndSign(cipher, crypto.Ed25519GenerateFromSeed(make([]byte, 32)))
	assert.NoError(t, err)
	encoded = append(encoded, hmacsha256...)
	encoded = append(encoded, sign...)
	expected := []byte{
		0x03, // Version
		0x08,
		0xC8, // 200
		0x01,
		0x12,
		0x0a,
	}
	expected = append(expected, []byte("ciphertext")...)
	expected = append(expected, []byte{
		0x6f, 0x95, 0x35, 0x51, 0xdc, 0xdb, 0xcb, 0x03, 0x0b, 0x22, 0xa2, 0xa7, 0xa1, 0xb7, 0x4f, 0x1a,
		0xa3, 0xe9, 0x5c, 0x05, 0x5d, 0x56, 0xdc, 0x5b, 0x87, 0x73, 0x05, 0x42, 0x2a, 0x59, 0x9a, 0x9a,
		0x26, 0x7a, 0x8d, 0xba, 0x65, 0xb2, 0x17, 0x65, 0x51, 0x6f, 0x37, 0xf3, 0x8f, 0xa1, 0x70, 0xd0,
		0xc4, 0x06, 0x05, 0xdc, 0x17, 0x71, 0x5e, 0x63, 0x84, 0xbe, 0xec, 0x7b, 0xa0, 0xc4, 0x08, 0xb8,
		0x9b, 0xc5, 0x08, 0x16, 0xad, 0xe5, 0x43, 0x0c,
	}...)
	expected = append(expected, []byte("hmacsha2signature")...)
	assert.Equal(t, expected, encoded)
}
