package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// HMACSHA256 returns the hash message authentication code with SHA-256 of the input with the key.
func HMACSHA256(key, input []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(input)
	return hash.Sum(nil)
}

// SHA256 return the SHA-256 of the value.
func SHA256(value []byte) []byte {
	hash := sha256.New()
	hash.Write(value)
	return hash.Sum(nil)
}

// HKDFSHA256 is the key deivation function based on HMAC and returns a reader based on input. salt and info can both be nil.
// The reader can be used to read an arbitary length of bytes which are based on all parameters.
func HKDFSHA256(input, salt, info []byte) io.Reader {
	return hkdf.New(sha256.New, input, salt, info)
}
