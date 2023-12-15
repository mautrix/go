package utilities

import (
	"codeberg.org/DerLukas/goolm"
	"codeberg.org/DerLukas/goolm/crypto"
	"maunium.net/go/mautrix/id"
)

func Sha256(value []byte) []byte {
	return goolm.Base64Encode(crypto.SHA256((value)))
}

// VerifySignature verifies an ed25519 signature.
func VerifySignature(message []byte, key id.Ed25519, signature []byte) (ok bool, err error) {
	keyDecoded, err := goolm.Base64Decode([]byte(key))
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
