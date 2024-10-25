package olm_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/crypto/goolm/session"
	"maunium.net/go/mautrix/crypto/libolm"
)

// TestEncryptDecrypt_GoolmToLibolm tests encryption where goolm encrypts and libolm decrypts
func TestEncryptDecrypt_GoolmToLibolm(t *testing.T) {
	goolmOutbound, err := session.NewMegolmOutboundSession()
	require.NoError(t, err)

	libolmInbound, err := libolm.NewInboundGroupSession([]byte(goolmOutbound.Key()))
	require.NoError(t, err)

	for i := 0; i < 10; i++ {
		ciphertext, err := goolmOutbound.Encrypt([]byte(fmt.Sprintf("message %d", i)))
		require.NoError(t, err)

		plaintext, msgIdx, err := libolmInbound.Decrypt(ciphertext)
		assert.NoError(t, err)
		assert.Equal(t, []byte(fmt.Sprintf("message %d", i)), plaintext)
		assert.Equal(t, goolmOutbound.MessageIndex()-1, msgIdx)
	}
}

func TestEncryptDecrypt_LibolmToGoolm(t *testing.T) {
	libolmOutbound, err := libolm.NewOutboundGroupSession()
	require.NoError(t, err)
	goolmInbound, err := session.NewMegolmInboundSession([]byte(libolmOutbound.Key()))
	require.NoError(t, err)

	for i := 0; i < 10; i++ {
		ciphertext, err := libolmOutbound.Encrypt([]byte(fmt.Sprintf("message %d", i)))
		require.NoError(t, err)

		plaintext, msgIdx, err := goolmInbound.Decrypt(ciphertext)
		assert.NoError(t, err)
		assert.Equal(t, []byte(fmt.Sprintf("message %d", i)), plaintext)
		assert.Equal(t, libolmOutbound.MessageIndex()-1, msgIdx)
	}
}
