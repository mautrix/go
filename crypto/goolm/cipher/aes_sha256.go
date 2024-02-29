package cipher

import (
	"bytes"
	"io"

	"github.com/element-hq/mautrix-go/crypto/goolm/crypto"
)

// derivedAESKeys stores the derived keys for the AESSHA256 cipher
type derivedAESKeys struct {
	key     []byte
	hmacKey []byte
	iv      []byte
}

// deriveAESKeys derives three keys for the AESSHA256 cipher
func deriveAESKeys(kdfInfo []byte, key []byte) (*derivedAESKeys, error) {
	hkdf := crypto.HKDFSHA256(key, nil, kdfInfo)
	keys := &derivedAESKeys{
		key:     make([]byte, 32),
		hmacKey: make([]byte, 32),
		iv:      make([]byte, 16),
	}
	if _, err := io.ReadFull(hkdf, keys.key); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(hkdf, keys.hmacKey); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(hkdf, keys.iv); err != nil {
		return nil, err
	}
	return keys, nil
}

// AESSha512BlockSize resturns the blocksize of the cipher AESSHA256.
func AESSha512BlockSize() int {
	return crypto.AESCBCBlocksize()
}

// AESSHA256 is a valid cipher using AES with CBC and HKDFSha256.
type AESSHA256 struct {
	kdfInfo []byte
}

// NewAESSHA256 returns a new AESSHA256 cipher with the key derive function info (kdfInfo).
func NewAESSHA256(kdfInfo []byte) *AESSHA256 {
	return &AESSHA256{
		kdfInfo: kdfInfo,
	}
}

// Encrypt encrypts the plaintext with the key. The key is used to derive the actual encryption key (32 bytes) as well as the iv (16 bytes).
func (c AESSHA256) Encrypt(key, plaintext []byte) (ciphertext []byte, err error) {
	keys, err := deriveAESKeys(c.kdfInfo, key)
	if err != nil {
		return nil, err
	}
	ciphertext, err = crypto.AESCBCEncrypt(keys.key, keys.iv, plaintext)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// Decrypt decrypts the ciphertext with the key. The key is used to derive the actual encryption key (32 bytes) as well as the iv (16 bytes).
func (c AESSHA256) Decrypt(key, ciphertext []byte) (plaintext []byte, err error) {
	keys, err := deriveAESKeys(c.kdfInfo, key)
	if err != nil {
		return nil, err
	}
	plaintext, err = crypto.AESCBCDecrypt(keys.key, keys.iv, ciphertext)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// MAC returns the MAC for the message using the key. The key is used to derive the actual mac key (32 bytes).
func (c AESSHA256) MAC(key, message []byte) ([]byte, error) {
	keys, err := deriveAESKeys(c.kdfInfo, key)
	if err != nil {
		return nil, err
	}
	return crypto.HMACSHA256(keys.hmacKey, message), nil
}

// Verify checks the MAC of the message using the key against the givenMAC. The key is used to derive the actual mac key (32 bytes).
func (c AESSHA256) Verify(key, message, givenMAC []byte) (bool, error) {
	mac, err := c.MAC(key, message)
	if err != nil {
		return false, err
	}
	return bytes.Equal(givenMAC, mac[:len(givenMAC)]), nil
}
