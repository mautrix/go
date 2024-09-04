package message_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

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
	expectedRaw := []byte("\x03\x08\xC8\x01\x12\x0aciphertexthmacsha2signature")
	hmacsha256 := []byte("hmacsha2")
	sign := []byte("signature")
	msg := message.GroupMessage{
		Version:      3,
		MessageIndex: 200,
		Ciphertext:   []byte("ciphertext"),
	}
	encoded, err := msg.EncodeAndMacAndSign(nil, nil, nil)
	assert.NoError(t, err)
	encoded = append(encoded, hmacsha256...)
	encoded = append(encoded, sign...)
	assert.Equal(t, expectedRaw, encoded)
}
