package session_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"

	"maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/crypto/goolm/session"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/id"
)

func TestOlmSession(t *testing.T) {
	pickleKey := []byte("secretKey")
	aliceKeyPair, err := crypto.Curve25519GenerateKey()
	assert.NoError(t, err)
	bobKeyPair, err := crypto.Curve25519GenerateKey()
	assert.NoError(t, err)
	bobOneTimeKey, err := crypto.Curve25519GenerateKey()
	assert.NoError(t, err)
	aliceSession, err := session.NewOutboundOlmSession(aliceKeyPair, bobKeyPair.PublicKey, bobOneTimeKey.PublicKey)
	assert.NoError(t, err)
	//create a message so that there are more keys to marshal
	plaintext := []byte("Test message from Alice to Bob")
	msgType, message, err := aliceSession.Encrypt(plaintext)
	assert.NoError(t, err)
	assert.Equal(t, id.OlmMsgTypePreKey, msgType)

	searchFunc := func(target crypto.Curve25519PublicKey) *crypto.OneTimeKey {
		if target.Equal(bobOneTimeKey.PublicKey) {
			return &crypto.OneTimeKey{
				Key:       bobOneTimeKey,
				Published: false,
				ID:        1,
			}
		}
		return nil
	}
	//bob receives message
	bobSession, err := session.NewInboundOlmSession(nil, message, searchFunc, bobKeyPair)
	assert.NoError(t, err)
	decryptedMsg, err := bobSession.Decrypt(string(message), msgType)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decryptedMsg)

	// Alice pickles session
	pickled, err := aliceSession.PickleAsJSON(pickleKey)
	assert.NoError(t, err)

	//bob sends a message
	plaintext = []byte("A message from Bob to Alice")
	msgType, message, err = bobSession.Encrypt(plaintext)
	assert.NoError(t, err)
	assert.Equal(t, id.OlmMsgTypeMsg, msgType)

	//Alice unpickles session
	newAliceSession, err := session.OlmSessionFromJSONPickled(pickled, pickleKey)
	assert.NoError(t, err)

	//Alice receives message
	decryptedMsg, err = newAliceSession.Decrypt(string(message), msgType)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decryptedMsg)

	//Alice receives message again
	_, err = newAliceSession.Decrypt(string(message), msgType)
	assert.ErrorIs(t, err, olm.ErrMessageKeyNotFound)

	//Alice sends another message
	plaintext = []byte("A second message to Bob")
	msgType, message, err = newAliceSession.Encrypt(plaintext)
	assert.NoError(t, err)
	assert.Equal(t, id.OlmMsgTypeMsg, msgType)

	//bob receives message
	decryptedMsg, err = bobSession.Decrypt(string(message), msgType)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decryptedMsg)
}

func TestSessionPickle(t *testing.T) {
	pickledDataFromLibOlm := []byte("icDKYm0b4aO23WgUuOxdpPoxC0UlEOYPVeuduNH3IkpFsmnWx5KuEOpxGiZw5IuB/sSn2RZUCTiJ90IvgC7AClkYGHep9O8lpiqQX73XVKD9okZDCAkBc83eEq0DKYC7HBkGRAU/4T6QPIBBY3UK4QZwULLE/fLsi3j4YZBehMtnlsqgHK0q1bvX4cRznZItVKR4ro0O9EAk6LLxJtSnRu5elSUk7YXT")
	pickleKey := []byte("secret_key")
	sess, err := session.OlmSessionFromPickled(pickledDataFromLibOlm, pickleKey)
	assert.NoError(t, err)
	newPickled, err := sess.Pickle(pickleKey)
	assert.NoError(t, err)
	assert.Equal(t, pickledDataFromLibOlm, newPickled)

	pickledDataFromLibOlm = append(pickledDataFromLibOlm, []byte("a")...)
	_, err = session.OlmSessionFromPickled(pickledDataFromLibOlm, pickleKey)
	assert.ErrorIs(t, err, base64.CorruptInputError(224))
}

func TestDecrypts(t *testing.T) {
	messages := [][]byte{
		{0x41, 0x77, 0x6F},
		{0x7f, 0xff, 0x6f, 0x01, 0x01, 0x34, 0x6d, 0x67, 0x12, 0x01},
		{0xee, 0x77, 0x6f, 0x41, 0x49, 0x6f, 0x67, 0x41, 0x77, 0x80, 0x41, 0x77, 0x77, 0x80, 0x41, 0x77, 0x6f, 0x67, 0x16, 0x67, 0x0a, 0x67, 0x7d, 0x6f, 0x67, 0x0a, 0x67, 0xc2, 0x67, 0x7d},
		{0xe9, 0xe9, 0xc9, 0xc1, 0xe9, 0xe9, 0xc9, 0xe9, 0xc9, 0xc1, 0xe9, 0xe9, 0xc9, 0xc1},
	}
	expectedErr := []error{
		olm.ErrInputToSmall,
		// Why are these being tested 🤔
		base64.CorruptInputError(0),
		base64.CorruptInputError(0),
		base64.CorruptInputError(0),
	}
	sessionPickled := []byte("E0p44KO2y2pzp9FIjv0rud2wIvWDi2dx367kP4Fz/9JCMrH+aG369HGymkFtk0+PINTLB9lQRt" +
		"ohea5d7G/UXQx3r5y4IWuyh1xaRnojEZQ9a5HRZSNtvmZ9NY1f1gutYa4UtcZcbvczN8b/5Bqg" +
		"e16cPUH1v62JKLlhoAJwRkH1wU6fbyOudERg5gdXA971btR+Q2V8GKbVbO5fGKL5phmEPVXyMs" +
		"rfjLdzQrgjOTxN8Pf6iuP+WFPvfnR9lDmNCFxJUVAdLIMnLuAdxf1TGcS+zzCzEE8btIZ99mHF" +
		"dGvPXeH8qLeNZA")
	pickleKey := []byte("")
	sess, err := session.OlmSessionFromPickled(sessionPickled, pickleKey)
	assert.NoError(t, err)
	for curIndex, curMessage := range messages {
		_, err := sess.Decrypt(string(curMessage), id.OlmMsgTypePreKey)
		assert.ErrorIs(t, err, expectedErr[curIndex])
	}
}
