package olm_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/crypto/goolm/session"
	"maunium.net/go/mautrix/crypto/libolm"
)

func TestMegolmOutboundSessionPickle_RoundtripThroughGoolm(t *testing.T) {
	libolmSession, err := libolm.NewOutboundGroupSession()
	require.NoError(t, err)
	libolmPickled, err := libolmSession.Pickle([]byte("test"))
	require.NoError(t, err)

	goolmSession, err := session.MegolmOutboundSessionFromPickled(libolmPickled, []byte("test"))
	require.NoError(t, err)

	goolmPickled, err := goolmSession.Pickle([]byte("test"))
	require.NoError(t, err)

	assert.Equal(t, libolmPickled, goolmPickled, "pickled versions are not the same")

	libolmSession2, err := libolm.NewOutboundGroupSession()
	require.NoError(t, err)
	err = libolmSession2.Unpickle(bytes.Clone(goolmPickled), []byte("test"))
	require.NoError(t, err)

	assert.Equal(t, libolmSession.Key(), libolmSession2.Key())
}

func TestMegolmOutboundSessionPickle_RoundtripThroughLibolm(t *testing.T) {
	goolmSession, err := session.NewMegolmOutboundSession()
	require.NoError(t, err)

	goolmPickled, err := goolmSession.Pickle([]byte("test"))
	require.NoError(t, err)

	libolmSession, err := libolm.NewOutboundGroupSession()
	require.NoError(t, err)
	err = libolmSession.Unpickle(bytes.Clone(goolmPickled), []byte("test"))
	require.NoError(t, err)

	libolmPickled, err := libolmSession.Pickle([]byte("test"))
	require.NoError(t, err)

	assert.Equal(t, goolmPickled, libolmPickled, "pickled versions are not the same")

	goolmSession2, err := session.MegolmOutboundSessionFromPickled(libolmPickled, []byte("test"))
	require.NoError(t, err)

	assert.Equal(t, goolmSession.Key(), goolmSession2.Key())
	assert.Equal(t, goolmSession.SigningKey.PrivateKey, goolmSession2.SigningKey.PrivateKey)
}

func TestMegolmOutboundSessionPickleLibolm(t *testing.T) {
	libolmSession, err := libolm.NewOutboundGroupSession()
	require.NoError(t, err)
	libolmPickled, err := libolmSession.Pickle([]byte("test"))
	require.NoError(t, err)

	goolmSession, err := session.MegolmOutboundSessionFromPickled(bytes.Clone(libolmPickled), []byte("test"))
	require.NoError(t, err)
	goolmPickled, err := goolmSession.Pickle([]byte("test"))
	require.NoError(t, err)

	assert.Equal(t, libolmPickled, goolmPickled, "pickled versions are not the same")
	assert.Equal(t, goolmSession.SigningKey.PrivateKey.PubKey(), goolmSession.SigningKey.PublicKey)

	// Ensure that the key export is the same and that the pickle is the same
	assert.Equal(t, libolmSession.Key(), goolmSession.Key(), "keys are not the same")
}

func TestMegolmOutboundSessionPickleGoolm(t *testing.T) {
	goolmSession, err := session.NewMegolmOutboundSession()
	require.NoError(t, err)
	goolmPickled, err := goolmSession.Pickle([]byte("test"))
	require.NoError(t, err)

	libolmSession, err := libolm.NewOutboundGroupSession()
	require.NoError(t, err)
	err = libolmSession.Unpickle(bytes.Clone(goolmPickled), []byte("test"))
	require.NoError(t, err)
	libolmPickled, err := libolmSession.Pickle([]byte("test"))
	require.NoError(t, err)

	assert.Equal(t, libolmPickled, goolmPickled, "pickled versions are not the same")
	assert.Equal(t, goolmSession.SigningKey.PrivateKey.PubKey(), goolmSession.SigningKey.PublicKey)

	// Ensure that the key export is the same and that the pickle is the same
	assert.Equal(t, libolmSession.Key(), goolmSession.Key(), "keys are not the same")
}

func FuzzMegolmOutboundSession_Encrypt(f *testing.F) {
	f.Add([]byte("anything"))

	f.Fuzz(func(t *testing.T, plaintext []byte) {
		if len(plaintext) == 0 {
			t.Skip("empty plaintext is not supported")
		}

		libolmSession, err := libolm.NewOutboundGroupSession()
		require.NoError(t, err)
		libolmPickled, err := libolmSession.Pickle([]byte("test"))
		require.NoError(t, err)

		goolmSession, err := session.MegolmOutboundSessionFromPickled(bytes.Clone(libolmPickled), []byte("test"))
		require.NoError(t, err)

		assert.Equal(t, libolmSession.Key(), goolmSession.Key())

		// Encrypt the plaintext ten times because the ratchet increments.
		for i := 0; i < 10; i++ {
			assert.EqualValues(t, i, libolmSession.MessageIndex())
			assert.EqualValues(t, i, goolmSession.MessageIndex())

			libolmEncrypted, err := libolmSession.Encrypt(plaintext)
			require.NoError(t, err)

			goolmEncrypted, err := goolmSession.Encrypt(plaintext)
			require.NoError(t, err)

			assert.Equal(t, libolmEncrypted, goolmEncrypted)

			assert.EqualValues(t, i+1, libolmSession.MessageIndex())
			assert.EqualValues(t, i+1, goolmSession.MessageIndex())
		}
	})
}
