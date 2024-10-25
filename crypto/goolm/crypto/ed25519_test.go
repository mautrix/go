package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/crypto/ed25519"
	"maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/crypto/goolm/libolmpickle"
)

const ed25519KeyPairPickleLength = ed25519.PublicKeySize + // PublicKey
	ed25519.PrivateKeySize // Private Key

func TestEd25519(t *testing.T) {
	keypair, err := crypto.Ed25519GenerateKey()
	assert.NoError(t, err)
	message := []byte("test message")
	signature, err := keypair.Sign(message)
	require.NoError(t, err)
	assert.True(t, keypair.Verify(message, signature))
}

func TestEd25519Case1(t *testing.T) {
	//64 bytes for ed25519 package
	keyPair, err := crypto.Ed25519GenerateKey()
	assert.NoError(t, err)
	message := []byte("Hello, World")

	keyPair2 := crypto.Ed25519GenerateFromPrivate(keyPair.PrivateKey)
	assert.Equal(t, keyPair, keyPair2, "not equal key pairs")
	signature, err := keyPair.Sign(message)
	require.NoError(t, err)
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
	encoder := libolmpickle.NewEncoder()
	keyPair.PickleLibOlm(encoder)
	assert.Len(t, encoder.Bytes(), ed25519KeyPairPickleLength)

	unpickledKeyPair := crypto.Ed25519KeyPair{}
	err = unpickledKeyPair.UnpickleLibOlm(libolmpickle.NewDecoder(encoder.Bytes()))
	assert.NoError(t, err)
	assert.Equal(t, keyPair, unpickledKeyPair)
}

func TestEd25519PicklePubKeyOnly(t *testing.T) {
	//create keypair
	keyPair, err := crypto.Ed25519GenerateKey()
	assert.NoError(t, err)
	//Remove privateKey
	keyPair.PrivateKey = nil
	encoder := libolmpickle.NewEncoder()
	keyPair.PickleLibOlm(encoder)
	assert.Len(t, encoder.Bytes(), ed25519KeyPairPickleLength)

	unpickledKeyPair := crypto.Ed25519KeyPair{}
	err = unpickledKeyPair.UnpickleLibOlm(libolmpickle.NewDecoder(encoder.Bytes()))
	assert.NoError(t, err)
	assert.Equal(t, keyPair, unpickledKeyPair)
}

func TestEd25519PicklePrivKeyOnly(t *testing.T) {
	//create keypair
	keyPair, err := crypto.Ed25519GenerateKey()
	assert.NoError(t, err)
	//Remove public
	keyPair.PublicKey = nil
	encoder := libolmpickle.NewEncoder()
	keyPair.PickleLibOlm(encoder)
	assert.Len(t, encoder.Bytes(), ed25519KeyPairPickleLength)

	unpickledKeyPair := crypto.Ed25519KeyPair{}
	err = unpickledKeyPair.UnpickleLibOlm(libolmpickle.NewDecoder(encoder.Bytes()))
	assert.NoError(t, err)
	assert.Equal(t, keyPair, unpickledKeyPair)
}
