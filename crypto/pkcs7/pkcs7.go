// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package pkcs7

import "bytes"

// Pad implements PKCS#7 padding as defined in [RFC2315]. It pads the plaintext
// to the given blockSize in the range [1, 255]. This is normally used in
// AES-CBC encryption.
//
// [RFC2315]: https://www.ietf.org/rfc/rfc2315.txt
func Pad(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	return append(plaintext, bytes.Repeat([]byte{byte(padding)}, padding)...)
}

// Unpad implements PKCS#7 unpadding as defined in [RFC2315]. It unpads the
// plaintext by reading the padding amount from the last byte of the plaintext.
// This is normally used in AES-CBC decryption.
//
// [RFC2315]: https://www.ietf.org/rfc/rfc2315.txt
func Unpad(plaintext []byte) []byte {
	length := len(plaintext)
	unpadding := int(plaintext[length-1])
	return plaintext[:length-unpadding]
}
