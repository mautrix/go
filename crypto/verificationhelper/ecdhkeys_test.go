package verificationhelper_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/crypto/verificationhelper"
)

func TestECDHPrivateKey(t *testing.T) {
	pk, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	private := verificationhelper.ECDHPrivateKey{pk}
	marshalled, err := json.Marshal(private)
	require.NoError(t, err)

	assert.Len(t, marshalled, 46)

	var unmarshalled verificationhelper.ECDHPrivateKey
	err = json.Unmarshal(marshalled, &unmarshalled)
	require.NoError(t, err)

	assert.True(t, private.Equal(unmarshalled.PrivateKey))
}

func TestECDHPublicKey(t *testing.T) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	public := private.PublicKey()

	pub := verificationhelper.ECDHPublicKey{public}
	marshalled, err := json.Marshal(pub)
	require.NoError(t, err)

	assert.Len(t, marshalled, 46)

	var unmarshalled verificationhelper.ECDHPublicKey
	err = json.Unmarshal(marshalled, &unmarshalled)
	require.NoError(t, err)

	assert.True(t, public.Equal(unmarshalled.PublicKey))
}
