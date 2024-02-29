package cipher_test

import (
	"bytes"
	"crypto/aes"
	"testing"

	"github.com/element-hq/mautrix-go/crypto/goolm/cipher"
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
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := cipher.Unpickle(key, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, toEncrypt) {
		t.Fatalf("Expected '%s' but got '%s'", toEncrypt, decoded)
	}
}
