package message_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"maunium.net/go/mautrix/crypto/goolm/aessha2"
	"maunium.net/go/mautrix/crypto/goolm/message"
)

func TestMessageDecode(t *testing.T) {
	messageRaw := []byte("\x03\x10\x01\n\nratchetkey\"\nciphertexthmacsha2")
	expectedRatchetKey := []byte("ratchetkey")
	expectedCipherText := []byte("ciphertext")

	msg := message.Message{}
	err := msg.Decode(messageRaw)
	assert.NoError(t, err)
	assert.EqualValues(t, 3, msg.Version)
	assert.True(t, msg.HasCounter)
	assert.EqualValues(t, 1, msg.Counter)
	assert.Equal(t, expectedCipherText, msg.Ciphertext)
	assert.EqualValues(t, expectedRatchetKey, msg.RatchetKey)
}

func TestMessageEncode(t *testing.T) {
	expectedRaw := []byte("\x03\n\nratchetkey\x10\x01\"\nciphertext\x95\x95\x92\x72\x04\x70\x56\xcdhmacsha2")
	hmacsha256 := []byte("hmacsha2")
	msg := message.Message{
		Version:    3,
		Counter:    1,
		RatchetKey: []byte("ratchetkey"),
		Ciphertext: []byte("ciphertext"),
	}
	cipher, err := aessha2.NewAESSHA2(nil, nil)
	assert.NoError(t, err)
	encoded, err := msg.EncodeAndMAC(cipher)
	assert.NoError(t, err)
	encoded = append(encoded, hmacsha256...)
	assert.Equal(t, expectedRaw, encoded)
}
