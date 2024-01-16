package olm

import (
	"crypto/sha256"
	"encoding/base64"
)

// SHA256B64 calculates the SHA-256 hash of the input and encodes it as base64.
func SHA256B64(input []byte) string {
	if len(input) == 0 {
		panic(EmptyInput)
	}
	hash := sha256.Sum256([]byte(input))
	return base64.RawStdEncoding.EncodeToString(hash[:])
}
