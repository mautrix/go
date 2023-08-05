// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package util

import (
	"crypto/rand"
	"encoding/binary"
	"hash/crc32"
	"strings"
	"unsafe"
)

func RandomBytes(n int) []byte {
	data := make([]byte, n)
	_, err := rand.Read(data)
	if err != nil {
		panic(err)
	}
	return data
}

const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// RandomStringBytes generates a random string of the given length and returns it as a byte array.
func RandomStringBytes(n int) []byte {
	if n <= 0 {
		return []byte{}
	}
	input := RandomBytes(n * 2)
	for i := 0; i < n; i++ {
		// Risk of modulo bias is only 2 in 65535, values between 0 and 65533 are uniformly distributed
		input[i] = letters[binary.BigEndian.Uint16(input[i*2:])%uint16(len(letters))]
	}
	input = input[:n]
	return input
}

// RandomString generates a random string of the given length.
func RandomString(n int) string {
	if n <= 0 {
		return ""
	}
	str := RandomStringBytes(n)
	return *(*string)(unsafe.Pointer(&str))
}

func base62Encode(val uint32, minWidth int) string {
	var buf strings.Builder
	for val > 0 {
		buf.WriteByte(letters[val%uint32(len(letters))])
		val /= 62
	}
	return strings.Repeat("0", minWidth-buf.Len()) + buf.String()
}

func RandomToken(namespace string, randomLength int) string {
	token := namespace + "_" + RandomString(randomLength)
	checksum := base62Encode(crc32.ChecksumIEEE([]byte(token)), 6)
	return token + "_" + checksum
}
