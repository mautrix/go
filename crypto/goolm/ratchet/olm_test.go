package ratchet_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/crypto/goolm/ratchet"
)

var (
	sharedSecret = []byte("A secret")
)

func initializeRatchets() (*ratchet.Ratchet, *ratchet.Ratchet, error) {
	ratchet.KdfInfo = struct {
		Root    []byte
		Ratchet []byte
	}{
		Root:    []byte("Olm"),
		Ratchet: []byte("OlmRatchet"),
	}
	aliceRatchet := ratchet.New()
	bobRatchet := ratchet.New()

	aliceKey, err := crypto.Curve25519GenerateKey()
	if err != nil {
		return nil, nil, err
	}

	aliceRatchet.InitializeAsAlice(sharedSecret, aliceKey)
	bobRatchet.InitializeAsBob(sharedSecret, aliceKey.PublicKey)
	return aliceRatchet, bobRatchet, nil
}

func TestSendReceive(t *testing.T) {
	aliceRatchet, bobRatchet, err := initializeRatchets()
	assert.NoError(t, err)

	plainText := []byte("Hello Bob")

	//Alice sends Bob a message
	encryptedMessage, err := aliceRatchet.Encrypt(plainText)
	assert.NoError(t, err)

	decrypted, err := bobRatchet.Decrypt(encryptedMessage)
	assert.NoError(t, err)
	assert.Equal(t, plainText, decrypted)

	//Bob sends Alice a message
	plainText = []byte("Hello Alice")
	encryptedMessage, err = bobRatchet.Encrypt(plainText)
	assert.NoError(t, err)
	decrypted, err = aliceRatchet.Decrypt(encryptedMessage)
	assert.NoError(t, err)
	assert.Equal(t, plainText, decrypted)
}

func TestOutOfOrder(t *testing.T) {
	aliceRatchet, bobRatchet, err := initializeRatchets()
	assert.NoError(t, err)

	plainText1 := []byte("First Message")
	plainText2 := []byte("Second Messsage. A bit longer than the first.")

	/* Alice sends Bob two messages and they arrive out of order */
	message1Encrypted, err := aliceRatchet.Encrypt(plainText1)
	assert.NoError(t, err)
	message2Encrypted, err := aliceRatchet.Encrypt(plainText2)
	assert.NoError(t, err)

	decrypted2, err := bobRatchet.Decrypt(message2Encrypted)
	assert.NoError(t, err)
	decrypted1, err := bobRatchet.Decrypt(message1Encrypted)
	assert.NoError(t, err)
	assert.Equal(t, plainText1, decrypted1)
	assert.Equal(t, plainText2, decrypted2)
}

func TestMoreMessages(t *testing.T) {
	aliceRatchet, bobRatchet, err := initializeRatchets()
	assert.NoError(t, err)
	plainText := []byte("These 15 bytes")
	for i := 0; i < 8; i++ {
		messageEncrypted, err := aliceRatchet.Encrypt(plainText)
		assert.NoError(t, err)

		decrypted, err := bobRatchet.Decrypt(messageEncrypted)
		assert.NoError(t, err)
		assert.Equal(t, plainText, decrypted)
	}
	for i := 0; i < 8; i++ {
		messageEncrypted, err := bobRatchet.Encrypt(plainText)
		assert.NoError(t, err)

		decrypted, err := aliceRatchet.Decrypt(messageEncrypted)
		assert.NoError(t, err)
		assert.Equal(t, plainText, decrypted)
	}
	messageEncrypted, err := aliceRatchet.Encrypt(plainText)
	assert.NoError(t, err)
	decrypted, err := bobRatchet.Decrypt(messageEncrypted)
	assert.NoError(t, err)
	assert.Equal(t, plainText, decrypted)
}

func TestJSONEncoding(t *testing.T) {
	aliceRatchet, bobRatchet, err := initializeRatchets()
	assert.NoError(t, err)
	marshaled, err := json.Marshal(aliceRatchet)
	assert.NoError(t, err)

	newRatcher := ratchet.Ratchet{}
	err = json.Unmarshal(marshaled, &newRatcher)
	assert.NoError(t, err)

	plainText := []byte("These 15 bytes")

	messageEncrypted, err := newRatcher.Encrypt(plainText)
	assert.NoError(t, err)
	decrypted, err := bobRatchet.Decrypt(messageEncrypted)
	assert.NoError(t, err)
	assert.Equal(t, plainText, decrypted)
}
