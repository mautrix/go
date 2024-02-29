package aescbc

import "errors"

var (
	ErrNoKeyProvided        = errors.New("no key")
	ErrIVNotBlockSize       = errors.New("IV length does not match AES block size")
	ErrNotMultipleBlockSize = errors.New("ciphertext length is not a multiple of the AES block size")
)
