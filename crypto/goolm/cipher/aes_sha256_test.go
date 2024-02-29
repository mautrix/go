package cipher

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestDeriveAESKeys(t *testing.T) {
	kdfInfo := []byte("test")
	key := []byte("test key")
	derivedKeys, err := deriveAESKeys(kdfInfo, key)
	if err != nil {
		t.Fatal(err)
	}
	derivedKeys2, err := deriveAESKeys(kdfInfo, key)
	if err != nil {
		t.Fatal(err)
	}
	//derivedKeys and derivedKeys2 should be identical
	if !bytes.Equal(derivedKeys.key, derivedKeys2.key) ||
		!bytes.Equal(derivedKeys.iv, derivedKeys2.iv) ||
		!bytes.Equal(derivedKeys.hmacKey, derivedKeys2.hmacKey) {
		t.Fail()
	}
	//changing kdfInfo
	kdfInfo = []byte("other kdf")
	derivedKeys2, err = deriveAESKeys(kdfInfo, key)
	if err != nil {
		t.Fatal(err)
	}
	//derivedKeys and derivedKeys2 should now be different
	if bytes.Equal(derivedKeys.key, derivedKeys2.key) ||
		bytes.Equal(derivedKeys.iv, derivedKeys2.iv) ||
		bytes.Equal(derivedKeys.hmacKey, derivedKeys2.hmacKey) {
		t.Fail()
	}
	//changing key
	key = []byte("other test key")
	derivedKeys, err = deriveAESKeys(kdfInfo, key)
	if err != nil {
		t.Fatal(err)
	}
	//derivedKeys and derivedKeys2 should now be different
	if bytes.Equal(derivedKeys.key, derivedKeys2.key) ||
		bytes.Equal(derivedKeys.iv, derivedKeys2.iv) ||
		bytes.Equal(derivedKeys.hmacKey, derivedKeys2.hmacKey) {
		t.Fail()
	}
}

func TestCipherAESSha256(t *testing.T) {
	key := []byte("test key")
	cipher := NewAESSHA256([]byte("testKDFinfo"))
	message := []byte("this is a random message for testing the implementation")
	//increase to next block size
	for len(message)%aes.BlockSize != 0 {
		message = append(message, []byte("-")...)
	}
	encrypted, err := cipher.Encrypt(key, []byte(message))
	if err != nil {
		t.Fatal(err)
	}
	mac, err := cipher.MAC(key, encrypted)
	if err != nil {
		t.Fatal(err)
	}

	verified, err := cipher.Verify(key, encrypted, mac[:8])
	if err != nil {
		t.Fatal(err)
	}
	if !verified {
		t.Fatal("signature verification failed")
	}
	resultPlainText, err := cipher.Decrypt(key, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, resultPlainText) {
		t.Fail()
	}
}
