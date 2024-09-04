package cipher_test

import (
	"crypto/aes"
	"testing"

	"github.com/stretchr/testify/assert"

	"maunium.net/go/mautrix/crypto/goolm/cipher"
)

func TestEncoding(t *testing.T) {
	key := []byte("test key")
	input := []byte("test")
	//pad marshaled to get block size
	toEncrypt := input
	if len(input)%aes.BlockSize != 0 {
		padding := aes.BlockSize - len(input)%aes.BlockSize
		toEncrypt = make([]byte, len(input)+padding)
		copy(toEncrypt, input)
	}
	encoded, err := cipher.Pickle(key, toEncrypt)
	assert.NoError(t, err)

	decoded, err := cipher.Unpickle(key, encoded)
	assert.NoError(t, err)
	assert.Equal(t, toEncrypt, decoded)
}
