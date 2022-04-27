package attachment

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
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
const random32Bytes = "\x85\xb4\x16/\xcaO\x1d\xe6\x7f\x95\xeb\xdb+g\x11\xb1\x81\x1a\xafY\x00\x1dq!h{\x81F\xaa\xd7A\x00"

func parseHelloWorld() *EncryptedFile {
	file := &EncryptedFile{}
	_ = json.Unmarshal([]byte(helloWorldRawFile), file)
	return file
}

func TestDecryptHelloWorld(t *testing.T) {
	file := parseHelloWorld()
	data := []byte(helloWorldCiphertext)
	err := file.DecryptInPlace(data)
	assert.NoError(t, err, "failed to decrypt file")
	assert.Equal(t, "hello world", string(data), "unexpected decrypt output")
}

func TestEncryptHelloWorld(t *testing.T) {
	file := parseHelloWorld()
	data := []byte("hello world")
	file.EncryptInPlace(data)
	assert.Equal(t, helloWorldCiphertext, string(data), "unexpected encrypt output")
}

func TestUnsupportedVersion(t *testing.T) {
	file := parseHelloWorld()
	file.Version = "foo"
	err := file.DecryptInPlace([]byte(helloWorldCiphertext))
	assert.ErrorIs(t, err, UnsupportedVersion)
}

func TestUnsupportedAlgorithm(t *testing.T) {
	file := parseHelloWorld()
	file.Key.Algorithm = "bar"
	err := file.DecryptInPlace([]byte(helloWorldCiphertext))
	assert.ErrorIs(t, err, UnsupportedAlgorithm)
}

func TestHashMismatch(t *testing.T) {
	file := parseHelloWorld()
	file.Hashes.SHA256 = base64.RawStdEncoding.EncodeToString([]byte(random32Bytes))
	err := file.DecryptInPlace([]byte(helloWorldCiphertext))
	assert.ErrorIs(t, err, HashMismatch)
}

func TestTooLongHash(t *testing.T) {
	file := parseHelloWorld()
	file.Hashes.SHA256 = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVlciBhZGlwaXNjaW5nIGVsaXQuIFNlZCBwb3N1ZXJlIGludGVyZHVtIHNlbS4gUXVpc3F1ZSBsaWd1bGEgZXJvcyB1bGxhbWNvcnBlciBxdWlzLCBsYWNpbmlhIHF1aXMgZmFjaWxpc2lzIHNlZCBzYXBpZW4uCg"
	err := file.DecryptInPlace([]byte(helloWorldCiphertext))
	assert.ErrorIs(t, err, InvalidHash)
}

func TestTooShortHash(t *testing.T) {
	file := parseHelloWorld()
	file.Hashes.SHA256 = "5/Gy1JftyyQ"
	err := file.DecryptInPlace([]byte(helloWorldCiphertext))
	assert.ErrorIs(t, err, InvalidHash)
}
