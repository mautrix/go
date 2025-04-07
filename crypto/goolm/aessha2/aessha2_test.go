package aessha2_test

import (
	"crypto/aes"
	"testing"

	"github.com/stretchr/testify/assert"

	"maunium.net/go/mautrix/crypto/goolm/aessha2"
)

func TestCipherAESSha256(t *testing.T) {
	key := []byte("test key")
	cipher, err := aessha2.NewAESSHA2(key, []byte("testKDFinfo"))
	assert.NoError(t, err)
	message := []byte("this is a random message for testing the implementation")
	//increase to next block size
	for len(message)%aes.BlockSize != 0 {
		message = append(message, []byte("-")...)
	}
	encrypted, err := cipher.Encrypt([]byte(message))
	assert.NoError(t, err)
	mac, err := cipher.MAC(encrypted)
	assert.NoError(t, err)

	verified, err := cipher.VerifyMAC(encrypted, mac[:8])
	assert.NoError(t, err)
	assert.True(t, verified, "signature verification failed")

	resultPlainText, err := cipher.Decrypt(encrypted)
	assert.NoError(t, err)
	assert.Equal(t, message, resultPlainText)
}
