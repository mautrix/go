package utilities

import (
	"encoding/base64"

	"maunium.net/go/mautrix/crypto/goolm"
	"maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/id"
)

// VerifySignature verifies an ed25519 signature.
func VerifySignature(message []byte, key id.Ed25519, signature []byte) (ok bool, err error) {
	keyDecoded, err := base64.RawStdEncoding.DecodeString(string(key))
	if err != nil {
		return false, err
	}
	signatureDecoded, err := goolm.Base64Decode(signature)
	if err != nil {
		return false, err
	}
	publicKey := crypto.Ed25519PublicKey(keyDecoded)
	return publicKey.Verify(message, signatureDecoded), nil
}
