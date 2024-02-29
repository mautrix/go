package backup_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/element-hq/mautrix-go/crypto/backup"
)

type testStruct struct {
	EphemeralKey *backup.EphemeralKey `json:"ephemeral"`
}

func TestEphemeralKey_UnmarshalJSON(t *testing.T) {
	testCases := []string{
		"o43y/Mck1DExWdHr0+qbPJbjzO97+RH1mw6phLhYQj0",
	}

	testJSONTemplate := `{"ephemeral": "%s"}`

	for _, tc := range testCases {
		t.Run(tc, func(t *testing.T) {
			var test testStruct
			jsonInput := fmt.Sprintf(testJSONTemplate, tc)
			err := json.Unmarshal([]byte(jsonInput), &test)
			require.NoError(t, err)
			expected, err := base64.RawStdEncoding.DecodeString(tc)
			require.NoError(t, err)
			assert.Equal(t, expected, test.EphemeralKey.Bytes())
		})
	}
}

func TestEphemeralKey_MarshallJSON(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	test := &backup.EphemeralKey{key.PublicKey()}
	marshalled, err := json.Marshal(test)
	require.NoError(t, err)
	assert.EqualValues(t, '"', marshalled[0])
	assert.Len(t, marshalled, 45)
	assert.EqualValues(t, '"', marshalled[44])
}
