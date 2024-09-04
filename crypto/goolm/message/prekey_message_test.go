package message_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/crypto/goolm/message"
)

func TestPreKeyMessageDecode(t *testing.T) {
	//Keys are 32 bytes to pass field check
	//Added a tag for an integer of 0 just for checkes
	messageRaw := []byte("\x03\x0a\x20onetimeKey.-.-.-.-.-.-.-.-.-.-.-\x1a\x20idKeywithlendth32bytes-.-.-.-.-.\x12\x20baseKey-.-.-.-.-.-.-.-.-.-.-.-.-\x22\x07message\x00\x00")
	expectedOneTimeKey := []byte("onetimeKey.-.-.-.-.-.-.-.-.-.-.-")
	expectedIdKey := []byte("idKeywithlendth32bytes-.-.-.-.-.")
	expectedbaseKey := []byte("baseKey-.-.-.-.-.-.-.-.-.-.-.-.-")
	expectedmessage := []byte("message")

	msg := message.PreKeyMessage{}
	err := msg.Decode(messageRaw)
	assert.NoError(t, err)
	assert.EqualValues(t, 3, msg.Version)
	assert.EqualValues(t, expectedOneTimeKey, msg.OneTimeKey)
	assert.EqualValues(t, expectedIdKey, msg.IdentityKey)
	assert.EqualValues(t, expectedbaseKey, msg.BaseKey)
	assert.Equal(t, expectedmessage, msg.Message)
	theirIDKey := crypto.Curve25519PublicKey(expectedIdKey)
	assert.True(t, msg.CheckFields(&theirIDKey), "field check failed")
}

func TestPreKeyMessageEncode(t *testing.T) {
	expectedRaw := []byte("\x03\x0a\x0aonetimeKey\x1a\x05idKey\x12\x07baseKey\x22\x07message")
	msg := message.PreKeyMessage{
		Version:     3,
		IdentityKey: []byte("idKey"),
		BaseKey:     []byte("baseKey"),
		OneTimeKey:  []byte("onetimeKey"),
		Message:     []byte("message"),
	}
	encoded, err := msg.Encode()
	assert.NoError(t, err)
	assert.Equal(t, expectedRaw, encoded)
}
