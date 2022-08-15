// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package util

import (
	"crypto/rand"
	"encoding/base64"
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

var letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// RandomString generates a random string of the given length.
func RandomString(n int) string {
	decodedLength := base64.RawStdEncoding.DecodedLen(n)
	output := make([]byte, n)
	base64.RawStdEncoding.Encode(output, RandomBytes(decodedLength))
	for i, char := range output {
		if char == '+' || char == '/' {
			_, err := rand.Read(output[i : i+1])
			if err != nil {
				panic(err)
			}
			output[i] = letters[int(output[i])%len(letters)]
		}
	}
	return *(*string)(unsafe.Pointer(&output))
}
