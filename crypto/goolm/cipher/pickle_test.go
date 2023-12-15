package cipher

import (
	"bytes"
	"crypto/aes"
	"testing"
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
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := Unpickle(key, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, toEncrypt) {
		t.Fatalf("Expected '%s' but got '%s'", toEncrypt, decoded)
	}
}
