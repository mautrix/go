package libolmpickle

import (
	"crypto/aes"
	"testing"

	"github.com/stretchr/testify/assert"
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
	encoded, err := Pickle(key, toEncrypt)
	assert.NoError(t, err)

	decoded, err := Unpickle(key, encoded)
	assert.NoError(t, err)
	assert.Equal(t, toEncrypt, decoded)
}
