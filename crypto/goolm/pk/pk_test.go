package pk_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"

	"maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/crypto/goolm/pk"
)

func TestSigning(t *testing.T) {
	seed := []byte{
		0x77, 0x07, 0x6D, 0x0A, 0x73, 0x18, 0xA5, 0x7D,
		0x3C, 0x16, 0xC1, 0x72, 0x51, 0xB2, 0x66, 0x45,
		0xDF, 0x4C, 0x2F, 0x87, 0xEB, 0xC0, 0x99, 0x2A,
		0xB1, 0x77, 0xFB, 0xA5, 0x1D, 0xB9, 0x2C, 0x2A,
	}
	message := []byte("We hold these truths to be self-evident, that all men are created equal, that they are endowed by their Creator with certain unalienable Rights, that among these are Life, Liberty and the pursuit of Happiness.")
	signing, _ := pk.NewSigningFromSeed(seed)
	signature, err := signing.Sign(message)
	assert.NoError(t, err)
	signatureDecoded, err := base64.RawStdEncoding.DecodeString(string(signature))
	assert.NoError(t, err)
	pubKeyEncoded := signing.PublicKey()
	pubKeyDecoded, err := base64.RawStdEncoding.DecodeString(string(pubKeyEncoded))
	assert.NoError(t, err)
	pubKey := crypto.Ed25519PublicKey(pubKeyDecoded)

	verified := pubKey.Verify(message, signatureDecoded)
	assert.True(t, verified, "signature did not verify")

	copy(signatureDecoded[0:], []byte("m"))
	verified = pubKey.Verify(message, signatureDecoded)
	assert.False(t, verified, "signature verified with wrong message")
}
