package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"maunium.net/go/mautrix/crypto/goolm/crypto"
)

func TestEd25519(t *testing.T) {
	keypair, err := crypto.Ed25519GenerateKey()
	assert.NoError(t, err)
	message := []byte("test message")
	signature := keypair.Sign(message)
	assert.True(t, keypair.Verify(message, signature))
}

func TestEd25519Case1(t *testing.T) {
	//64 bytes for ed25519 package
	keyPair, err := crypto.Ed25519GenerateKey()
	assert.NoError(t, err)
	message := []byte("Hello, World")

	keyPair2 := crypto.Ed25519GenerateFromPrivate(keyPair.PrivateKey)
	assert.Equal(t, keyPair, keyPair2, "not equal key pairs")
	signature := keyPair.Sign(message)
	verified := keyPair.Verify(message, signature)
	assert.True(t, verified, "message did not verify although it should")

	//Now change the message and verify again
	message = append(message, []byte("a")...)
	verified = keyPair.Verify(message, signature)
	assert.False(t, verified, "message did verify although it should not")
}

func TestEd25519Pickle(t *testing.T) {
	//create keypair
	keyPair, err := crypto.Ed25519GenerateKey()
	assert.NoError(t, err)
	target := make([]byte, crypto.Ed25519KeyPairPickleLength)
	writtenBytes, err := keyPair.PickleLibOlm(target)
	assert.NoError(t, err)
	assert.Len(t, target, writtenBytes)

	unpickledKeyPair := crypto.Ed25519KeyPair{}
	readBytes, err := unpickledKeyPair.UnpickleLibOlm(target)
	assert.NoError(t, err)
	assert.Len(t, target, readBytes, "read bytes not correct")
	assert.Equal(t, keyPair, unpickledKeyPair)
}

func TestEd25519PicklePubKeyOnly(t *testing.T) {
	//create keypair
	keyPair, err := crypto.Ed25519GenerateKey()
	assert.NoError(t, err)
	//Remove privateKey
	keyPair.PrivateKey = nil
	target := make([]byte, crypto.Ed25519KeyPairPickleLength)
	writtenBytes, err := keyPair.PickleLibOlm(target)
	assert.NoError(t, err)
	assert.Len(t, target, writtenBytes)

	unpickledKeyPair := crypto.Ed25519KeyPair{}
	readBytes, err := unpickledKeyPair.UnpickleLibOlm(target)
	assert.NoError(t, err)
	assert.Len(t, target, readBytes, "read bytes not correct")
	assert.Equal(t, keyPair, unpickledKeyPair)
}

func TestEd25519PicklePrivKeyOnly(t *testing.T) {
	//create keypair
	keyPair, err := crypto.Ed25519GenerateKey()
	assert.NoError(t, err)
	//Remove public
	keyPair.PublicKey = nil
	target := make([]byte, crypto.Ed25519KeyPairPickleLength)
	writtenBytes, err := keyPair.PickleLibOlm(target)
	assert.NoError(t, err)
	assert.Len(t, target, writtenBytes)

	unpickledKeyPair := crypto.Ed25519KeyPair{}
	readBytes, err := unpickledKeyPair.UnpickleLibOlm(target)
	assert.NoError(t, err)
	assert.Len(t, target, readBytes, "read bytes not correct")
	assert.Equal(t, keyPair, unpickledKeyPair)
}
