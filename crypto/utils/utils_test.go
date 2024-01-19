// Copyright (c) 2020 Nikos Filippakis
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package utils

import (
	"encoding/base64"
	"testing"
)

func TestAES256Ctr(t *testing.T) {
	expected := "Hello world"
	key, iv := GenAttachmentA256CTR()
	enc := XorA256CTR([]byte(expected), key, iv)
	dec := XorA256CTR(enc, key, iv)
	if string(dec) != expected {
		t.Errorf("Expected decrypted using generated key/iv to be `%v`, got %v", expected, string(dec))
	}

	var key2 [AESCTRKeyLength]byte
	var iv2 [AESCTRIVLength]byte
	for i := 0; i < AESCTRKeyLength; i++ {
		key2[i] = byte(i)
	}
	for i := 0; i < AESCTRIVLength; i++ {
		iv2[i] = byte(i) + 32
	}
	dec2 := XorA256CTR([]byte{0x29, 0xc3, 0xff, 0x02, 0x21, 0xaf, 0x67, 0x73, 0x6e, 0xad, 0x9d}, key2, iv2)
	if string(dec2) != expected {
		t.Errorf("Expected decrypted using constant key/iv to be `%v`, got %v", expected, string(dec2))
	}
}

func TestPBKDF(t *testing.T) {
	salt := make([]byte, 16)
	for i := 0; i < 16; i++ {
		salt[i] = byte(i)
	}
	key := PBKDF2SHA512([]byte("Hello world"), salt, 1000, 256)
	expected := "ffk9YdbVE1cgqOWgDaec0lH+rJzO+MuCcxpIn3Z6D0E="
	keyB64 := base64.StdEncoding.EncodeToString([]byte(key))
	if keyB64 != expected {
		t.Errorf("Expected base64 of generated key to be `%v`, got `%v`", expected, keyB64)
	}
}

func TestDecodeSSSSKey(t *testing.T) {
	recoveryKey := "EsTL 2cTx 9Qy1 8TVd qGsn GDrD i5dT EEuX Qz8U P7hi Z7uu U8wZ"
	decoded := DecodeBase58RecoveryKey(recoveryKey)

	expected := "QCFDrXZYLEFnwf4NikVm62rYGJS2mNBEmAWLC3CgNPw="
	decodedB64 := base64.StdEncoding.EncodeToString(decoded[:])
	if expected != decodedB64 {
		t.Errorf("Expected decoded recovery key b64 to be `%v`, got `%v`", expected, decodedB64)
	}

	if encoded := EncodeBase58RecoveryKey(decoded); encoded != recoveryKey {
		t.Errorf("Expected recovery key to be `%v`, got `%v`", recoveryKey, encoded)
	}
}

func TestKeyDerivationAndHMAC(t *testing.T) {
	recoveryKey := "EsUG Ddi6 e1Cm F4um g38u JN72 d37v Q2ry qCf2 rKgL E2MQ ZQz6"
	decoded := DecodeBase58RecoveryKey(recoveryKey)

	aesKey, hmacKey := DeriveKeysSHA256(decoded[:], "m.cross_signing.master")

	ciphertextBytes, err := base64.StdEncoding.DecodeString("Fx16KlJ9vkd3Dd6CafIq5spaH5QmK5BALMzbtFbQznG2j1VARKK+klc4/Qo=")
	if err != nil {
		t.Error(err)
	}

	calcMac := HMACSHA256B64(ciphertextBytes, hmacKey)
	expectedMac := "0DABPNIZsP9iTOh1o6EM0s7BfHHXb96dN7Eca88jq2E"
	if calcMac != expectedMac {
		t.Errorf("Expected MAC `%v`, got `%v`", expectedMac, calcMac)
	}

	var ivBytes [AESCTRIVLength]byte
	decodedIV, _ := base64.StdEncoding.DecodeString("zxT/W5LpZ0Q819pfju6hZw==")
	copy(ivBytes[:], decodedIV)
	decrypted := string(XorA256CTR(ciphertextBytes, aesKey, ivBytes))

	expectedDec := "Ec8eZDyvVkO3EDsEG6ej5c0cCHnX7PINqFXZjnaTV2s="
	if expectedDec != decrypted {
		t.Errorf("Expected decrypted text to be `%v`, got `%v`", expectedDec, decrypted)
	}
}
