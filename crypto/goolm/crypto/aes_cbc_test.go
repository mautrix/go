package crypto_test

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"testing"

	"github.com/element-hq/mautrix-go/crypto/goolm/crypto"
)

func TestAESCBC(t *testing.T) {
	var ciphertext, plaintext []byte
	var err error

	// The key length can be 32, 24, 16  bytes (OR in bits: 128, 192 or 256)
	key := make([]byte, 32)
	_, err = rand.Read(key)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		t.Fatal(err)
	}
	plaintext = []byte("secret message for testing")
	//increase to next block size
	for len(plaintext)%8 != 0 {
		plaintext = append(plaintext, []byte("-")...)
	}

	if ciphertext, err = crypto.AESCBCEncrypt(key, iv, plaintext); err != nil {
		t.Fatal(err)
	}

	resultPlainText, err := crypto.AESCBCDecrypt(key, iv, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if string(resultPlainText) != string(plaintext) {
		t.Fatalf("message '%s' (length %d) != '%s'", resultPlainText, len(resultPlainText), plaintext)
	}
}

func TestAESCBCCase1(t *testing.T) {
	expected := []byte{
		0xDC, 0x95, 0xC0, 0x78, 0xA2, 0x40, 0x89, 0x89,
		0xAD, 0x48, 0xA2, 0x14, 0x92, 0x84, 0x20, 0x87,
		0xF3, 0xC0, 0x03, 0xDD, 0xC4, 0xA7, 0xB8, 0xA9,
		0x4B, 0xAE, 0xDF, 0xFC, 0x3D, 0x21, 0x4C, 0x38,
	}
	input := make([]byte, 16)
	key := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	encrypted, err := crypto.AESCBCEncrypt(key, iv, input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expected, encrypted) {
		t.Fatalf("encrypted did not match expected:\n%v\n%v\n", encrypted, expected)
	}

	decrypted, err := crypto.AESCBCDecrypt(key, iv, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, decrypted) {
		t.Fatalf("decrypted did not match expected:\n%v\n%v\n", decrypted, input)
	}
}
