package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/element-hq/mautrix-go/crypto/goolm"
)

// AESCBCBlocksize returns the blocksize of the encryption method
func AESCBCBlocksize() int {
	return aes.BlockSize
}

// AESCBCEncrypt encrypts the plaintext with the key and iv. len(iv) must be equal to the blocksize!
func AESCBCEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("AESCBCEncrypt: %w", goolm.ErrNoKeyProvided)
	}
	if len(iv) != AESCBCBlocksize() {
		return nil, fmt.Errorf("iv: %w", goolm.ErrNotBlocksize)
	}
	var cipherText []byte
	plaintext = pkcs5Padding(plaintext, AESCBCBlocksize())
	if len(plaintext)%AESCBCBlocksize() != 0 {
		return nil, fmt.Errorf("message: %w", goolm.ErrNotMultipleBlocksize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cipherText = make([]byte, len(plaintext))
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(cipherText, plaintext)
	return cipherText, nil
}

// AESCBCDecrypt decrypts the ciphertext with the key and iv. len(iv) must be equal to the blocksize!
func AESCBCDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("AESCBCEncrypt: %w", goolm.ErrNoKeyProvided)
	}
	if len(iv) != AESCBCBlocksize() {
		return nil, fmt.Errorf("iv: %w", goolm.ErrNotBlocksize)
	}
	var block cipher.Block
	var err error
	block, err = aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < AESCBCBlocksize() {
		return nil, fmt.Errorf("ciphertext: %w", goolm.ErrNotMultipleBlocksize)
	}

	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(ciphertext, ciphertext)
	return pkcs5Unpadding(ciphertext), nil
}

// pkcs5Padding paddes the plaintext to be used in the AESCBC encryption.
func pkcs5Padding(plaintext []byte, blockSize int) []byte {
	padding := (blockSize - len(plaintext)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padtext...)
}

// pkcs5Unpadding undoes the padding to the plaintext after AESCBC decryption.
func pkcs5Unpadding(plaintext []byte) []byte {
	length := len(plaintext)
	unpadding := int(plaintext[length-1])
	return plaintext[:(length - unpadding)]
}
