package pkcs7_test

import (
	"bytes"
	"crypto/aes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/element-hq/mautrix-go/crypto/pkcs7"
)

func TestPKCS7(t *testing.T) {
	testCases := []struct {
		input    []byte
		blockLen int
		expected []byte
	}{
		{[]byte("test"), 4, []byte("test\x04\x04\x04\x04")},
		{[]byte("test"), 8, []byte("test\x04\x04\x04\x04")},
		{[]byte("test1"), 8, []byte("test1\x03\x03\x03")},
		{bytes.Repeat([]byte("test1"), 6), aes.BlockSize, append(bytes.Repeat([]byte("test1"), 6), 0x02, 0x02)},
	}
	for _, tc := range testCases {
		t.Run(string(tc.input), func(t *testing.T) {
			// Test pad
			padded := pkcs7.Pad(tc.input, tc.blockLen)
			assert.Equal(t, tc.expected, padded)
			assert.Zero(t, len(padded)%tc.blockLen, "padded length is not a multiple of block size")

			// Test unpad
			assert.Equal(t, tc.input, pkcs7.Unpad(tc.expected))
		})
	}
}

func TestPKCS7_RoundtripWithAESBlockSize(t *testing.T) {
	for i := 0; i < 1024; i++ {
		input := bytes.Repeat([]byte{byte(i)}, i)
		padded := pkcs7.Pad(input, aes.BlockSize)
		assert.Zero(t, len(padded)%aes.BlockSize, "padded length is not a multiple of the AES block size")
		unpadded := pkcs7.Unpad(padded)
		assert.Equal(t, bytes.Repeat([]byte{byte(i)}, i), unpadded)
	}
}
