package cipher

import (
	"crypto/aes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeriveAESKeys(t *testing.T) {
	derivedKeys, err := deriveAESKeys([]byte("test"), []byte("test key"))
	assert.NoError(t, err)
	derivedKeys2, err := deriveAESKeys([]byte("test"), []byte("test key"))
	assert.NoError(t, err)

	//derivedKeys and derivedKeys2 should be identical
	assert.Equal(t, derivedKeys.key, derivedKeys2.key)
	assert.Equal(t, derivedKeys.iv, derivedKeys2.iv)
	assert.Equal(t, derivedKeys.hmacKey, derivedKeys2.hmacKey)

	//changing kdfInfo
	derivedKeys2, err = deriveAESKeys([]byte("other kdf"), []byte("test key"))
	assert.NoError(t, err)

	//derivedKeys and derivedKeys2 should now be different
	assert.NotEqual(t, derivedKeys.key, derivedKeys2.key)
	assert.NotEqual(t, derivedKeys.iv, derivedKeys2.iv)
	assert.NotEqual(t, derivedKeys.hmacKey, derivedKeys2.hmacKey)

	//changing key
	derivedKeys, err = deriveAESKeys([]byte("test"), []byte("other test key"))
	assert.NoError(t, err)

	//derivedKeys and derivedKeys2 should now be different
	assert.NotEqual(t, derivedKeys.key, derivedKeys2.key)
	assert.NotEqual(t, derivedKeys.iv, derivedKeys2.iv)
	assert.NotEqual(t, derivedKeys.hmacKey, derivedKeys2.hmacKey)
}

func TestCipherAESSha256(t *testing.T) {
	key := []byte("test key")
	cipher := NewAESSHA256([]byte("testKDFinfo"))
	message := []byte("this is a random message for testing the implementation")
	//increase to next block size
	for len(message)%aes.BlockSize != 0 {
		message = append(message, []byte("-")...)
	}
	encrypted, err := cipher.Encrypt(key, []byte(message))
	assert.NoError(t, err)
	mac, err := cipher.MAC(key, encrypted)
	assert.NoError(t, err)

	verified, err := cipher.Verify(key, encrypted, mac[:8])
	assert.NoError(t, err)
	assert.True(t, verified, "signature verification failed")

	resultPlainText, err := cipher.Decrypt(key, encrypted)
	assert.NoError(t, err)
	assert.Equal(t, message, resultPlainText)
}
