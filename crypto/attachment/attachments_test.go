package attachment

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

const helloWorldCiphertext = ":6\xc7O1yR\x06\xe8\xcf]"
const helloWorldRawFile = `{
  "v": "v2",
  "key": {
    "kty": "oct",
    "alg": "A256CTR",
    "ext": true,
    "k": "35XNdmWKOpn6UYS82Y83wEY8LagwQZHX2X0kAFW7sdg",
    "key_ops": [
      "encrypt",
      "decrypt"
    ]
  },
  "iv": "DOtPz8bC3qgAAAAAAAAAAA",
  "hashes": {
    "sha256": "rO+040ZhUxbpbmIS9GUuMSen4NPKFxMzqOUJeemM8mk"
  }
}`
const random16Bytes = "\x85\xb4\x16/\xcaO\x1d\xe6\x7f\x95\xeb\xdb+g\x11\xb1"

var random16BytesBase64 = base64.StdEncoding.EncodeToString([]byte(random16Bytes))

func parseHelloWorld() *EncryptedFile {
	file := &EncryptedFile{}
	_ = json.Unmarshal([]byte(helloWorldRawFile), file)
	return file
}

func TestDecryptHelloWorld(t *testing.T) {
	file := parseHelloWorld()
	plaintext, err := file.Decrypt([]byte(helloWorldCiphertext))
	if err != nil {
		t.Errorf("Failed to decrypt file: %v", err)
	} else if string(plaintext) != "hello world" {
		t.Errorf("Unexpected decrypt output: %v", plaintext)
	}
}

func TestEncryptHelloWorld(t *testing.T) {
	file := parseHelloWorld()
	ciphertext := file.Encrypt([]byte("hello world"))
	if string(ciphertext) != helloWorldCiphertext {
		t.Errorf("Unexpected encrypt output: %v", ciphertext)
	}
}

func TestUnsupportedVersion(t *testing.T) {
	file := parseHelloWorld()
	file.Version = "foo"
	_, err := file.Decrypt([]byte(helloWorldCiphertext))
	if err != UnsupportedVersion {
		t.Errorf("Didn't get expected UnsupportedVersion error: %v", err)
	}
}

func TestUnsupportedAlgorithm(t *testing.T) {
	file := parseHelloWorld()
	file.Key.Algorithm = "bar"
	_, err := file.Decrypt([]byte(helloWorldCiphertext))
	if err != UnsupportedAlgorithm {
		t.Errorf("Didn't get expected UnsupportedAlgorithm error: %v", err)
	}
}

func TestHashMismatch(t *testing.T) {
	file := parseHelloWorld()
	file.Hashes.SHA256 = random16BytesBase64
	_, err := file.Decrypt([]byte(helloWorldCiphertext))
	if err != HashMismatch {
		t.Errorf("Didn't get expected HashMismatch error: %v", err)
	}
}

func TestTooLongHash(t *testing.T) {
	file := parseHelloWorld()
	file.Hashes.SHA256 = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVlciBhZGlwaXNjaW5nIGVsaXQuIFNlZCBwb3N1ZXJlIGludGVyZHVtIHNlbS4gUXVpc3F1ZSBsaWd1bGEgZXJvcyB1bGxhbWNvcnBlciBxdWlzLCBsYWNpbmlhIHF1aXMgZmFjaWxpc2lzIHNlZCBzYXBpZW4uCg"
	_, err := file.Decrypt([]byte(helloWorldCiphertext))
	if err != HashMismatch {
		t.Errorf("Didn't get expected HashMismatch error: %v", err)
	}
}

func TestTooShortHash(t *testing.T) {
	file := parseHelloWorld()
	file.Hashes.SHA256 = "5/Gy1JftyyQ"
	_, err := file.Decrypt([]byte(helloWorldCiphertext))
	if err != HashMismatch {
		t.Errorf("Didn't get expected HashMismatch error: %v", err)
	}
}
