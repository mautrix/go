package ed25519_test

import (
	stdlibed25519 "crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mau.fi/util/random"

	"maunium.net/go/mautrix/crypto/ed25519"
)

func TestPubkeyEqual(t *testing.T) {
	pubkeyBytes := random.Bytes(32)
	pubkey := ed25519.PublicKey(pubkeyBytes)
	pubkey2 := ed25519.PublicKey(pubkeyBytes)
	stdlibPubkey := stdlibed25519.PublicKey(pubkeyBytes)
	assert.True(t, pubkey.Equal(pubkey2))
	assert.True(t, pubkey.Equal(stdlibPubkey))
}
