package backup_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/element-hq/mautrix-go/crypto/backup"
	"github.com/element-hq/mautrix-go/id"
)

func TestEncryptedSessionData_Decrypt(t *testing.T) {
	testCases := []struct {
		encryptedJSON []byte
		expectedJSON  string
	}{
		{
			[]byte(`
				{
					"ciphertext": "hDCjEbyi2uMXt3RBWe9mRdeqhcoraPR84/cq5ll16LIIIICJ8ZLmiWG5IwmGqDFmd3Jw20cNo49b38LH3oBJUl5DG44VdjoI4nlgAzaMSLwMZ7JFGt0Enu1Csfgpvgt1qksTP6QB7YDwITD33iL7ucco1iOl7ABGzhyjCi2iZ3A6Xmx3RsAmHhmU5gJWE6/lIoI6/lh7dZFSfp4RTGfxQ8ToCCIsrgdx1weViv4I4ArXfcrdnaprPzP4cH77Ej1Wg1/bUHtB4C8nOiX+cYnOG29NbTHbtQF14zJpA+2XM2JngiLkss+NQj96PQzgPNhAMEFOLLy5ckY1WvS4sMMeCVzAyt5dwEGDcyxLTC4oJ/RrvLcHCHW0aOygPSlNoMRyDgC0f92+mPQGAmFv4GhfDFXfaauBxBdRAPjXj7Onn2B4UdfwQXGLT3RAihba8i9usOX5hLxqQqvtA3SUuV8hPrzHhpPEeRvx+PgZsXwV+gM7Aw3Mza6hwmILdngJh7NNQTINsCRqff9Ck3Kh7aSOoHsHvz7Ot+T514ObDwWYYCBMmS/6EG4XjSya6R98ggRWGrO9l21YYUvzBTv7OLtMck0Za3151Zqi/5LRKP95QIU",
					"ephemeral": "o43y/Mck1DExWdHr0+qbPJbjzO97+RH1mw6phLhYQj0",
					"mac": "Mnt8eXwFfjw"
				}
			`),
			`
				{
					"algorithm": "m.megolm.v1.aes-sha2",
					"sender_key": "JUUfV6vErSATm3rIOU9DML+IX1SlYxnAAS824xhbhC4",
					"session_key": "AQAAAABc1O9JP2/HXS22iLN1uScFv2UyL33/L3L0sysPKcovQFI0lwKTuutrVeww2SNOU9b2J62kV/QXEw7+N2I9klrvqqr9kdo1ywqFtZOnp8DlgR2+OhOnUYmj5YmJhmApPle9xnVVwZv57Q0REsmSAovHBLH4Kf3GEHPJ9WXEEnLINT9Gzit9qjIZ1fKKacLtvsZ+hbnTPvP5Df3ENalB+03E",
					"sender_claimed_keys": {"ed25519":"R2UJWSfgGr64iPENthl/98WGqBtnNlYuP12d6TEuGo4"},
					"forwarding_curve25519_key_chain": []
				}
			`,
		},
		{
			[]byte(`
				{
					"ciphertext": "vdLkqNTijkM1L7HmbxdZs1EHygC7GFG0wPTAaLqpOCoir3K6tNYbjIJs36vzrwawdmfPxZvA9p/k3bZIhZDP7IivGYe69+4pWiIzrwYkHCidigKXkYD8KxKWvakBquO9vWUssXC05xdkQjHMNJK3zSJgtkbMhoY28i1VUdmIjts4xU0cIT40F52Uyx3iu1UrqywUREEE5vhoSbeWxW3Vo5lqPi6rnyvMGZhVzAOv6re2O7wPWnSp0YJUsPaEj6Q9QpLr8BB9vJ++3kwmP5vxfjJLUsXuNEHWIKP5QyhpmGCgwjNpjnU6VhCqBzqs2M/KKX8zxZMGTIRidc3gx2i8KtDwRHRzh3FsSJEaC0sfCfGijpH5g9Pa+2P6b1GxvGQ4TF5X6ayLiV6FyNilpZ4z3kYsy63fP06uinHkX0TUClMQgLLmn0BAiOxKWtLNSLxgFdSYFm5oU/rpOBXWQKbzQ3cvlJZxBtxnaAhJnt3+t/3pJahlKAOxrQbKZAPL/KbO4nF9dsHpMkfMs25pVLDoHLKEXSBhagEFDbPKL5Uv55kca1C1XGrx+8fYUDBRQtYSLBSbAtF3UMv+hIMdRnmyQntwOy2hKRRs2UxnIlExk0Q",
					"ephemeral": "24PxRUfQDyYNZcTq0HT8pS3Gq+zkfsAcXHFJ3nZ56W4",
					"mac": "T7xq9qHm4Js"
				}
			`),
			`
				{
					"algorithm": "m.megolm.v1.aes-sha2",
					"sender_key": "JUUfV6vErSATm3rIOU9DML+IX1SlYxnAAS824xhbhC4",
					"session_key": "AQAAAAB6cP1PrdPeIG/B0ZRHNUc65ujvIzOxKhW1HN25efyZFaq9xsLvCngm4WO56gEuUhS16E4m0pAa9B/KyRz3AnSOVcHYh1bYxm9qf6zU5PFm255n6FR2lGN0vrgUM7Xu2GNUDCWoNI4m4QsiBor9eCj2ZJRay75dZ4nkhNf3GxBKOkhzPCreKabLxVsseGGIkq8rf01b0CWIcp5ISQISLdza",
					"sender_claimed_keys": {"ed25519":"R2UJWSfgGr64iPENthl/98WGqBtnNlYuP12d6TEuGo4"},
					"forwarding_curve25519_key_chain": []
				}
			`,
		},
	}

	keyBytes, err := base64.RawStdEncoding.DecodeString("ReSMMZeRtDSdrwXzu2OvN0B73KUXkYPt3kaYfFIkw10")
	require.NoError(t, err)
	backupKey, err := backup.MegolmBackupKeyFromBytes(keyBytes)
	require.NoError(t, err)

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("test case %d", i+1), func(t *testing.T) {
			var esd backup.EncryptedSessionData[backup.MegolmSessionData]
			err := json.Unmarshal([]byte(tc.encryptedJSON), &esd)
			assert.NoError(t, err)

			sessionData, err := esd.Decrypt(backupKey)
			require.NoError(t, err)

			sessionDataJSON, err := json.Marshal(sessionData)
			require.NoError(t, err)
			assert.JSONEq(t, string(tc.expectedJSON), string(sessionDataJSON))
		})
	}
}

func TestEncryptedSessionData_Roundtrip(t *testing.T) {
	backupKey, err := backup.NewMegolmBackupKey()
	require.NoError(t, err)

	sessionData := backup.MegolmSessionData{
		Algorithm: id.AlgorithmMegolmV1,
	}

	encrypted, err := backup.EncryptSessionData(backupKey, sessionData)
	require.NoError(t, err)

	encryptedJSON, err := json.Marshal(encrypted)
	require.NoError(t, err)

	var roundTrippedEncryptedSessionData backup.EncryptedSessionData[backup.MegolmSessionData]
	err = json.Unmarshal(encryptedJSON, &roundTrippedEncryptedSessionData)
	require.NoError(t, err)

	decrypted, err := roundTrippedEncryptedSessionData.Decrypt(backupKey)
	require.NoError(t, err)

	assert.Equal(t, id.AlgorithmMegolmV1, decrypted.Algorithm)
}
