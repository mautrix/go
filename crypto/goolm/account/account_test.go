package account_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"

	"maunium.net/go/mautrix/id"

	"maunium.net/go/mautrix/crypto/goolm/account"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/crypto/signatures"
)

func TestAccount(t *testing.T) {
	firstAccount, err := account.NewAccount()
	assert.NoError(t, err)
	err = firstAccount.GenFallbackKey()
	assert.NoError(t, err)
	err = firstAccount.GenOneTimeKeys(2)
	assert.NoError(t, err)
	encryptionKey := []byte("testkey")

	//now pickle account in JSON format
	pickled, err := firstAccount.PickleAsJSON(encryptionKey)
	assert.NoError(t, err)

	//now unpickle into new Account
	unpickledAccount, err := account.AccountFromJSONPickled(pickled, encryptionKey)
	assert.NoError(t, err)

	//check if accounts are the same
	assert.Equal(t, firstAccount.NextOneTimeKeyID, unpickledAccount.NextOneTimeKeyID)
	assert.Equal(t, firstAccount.CurrentFallbackKey, unpickledAccount.CurrentFallbackKey)
	assert.Equal(t, firstAccount.PrevFallbackKey, unpickledAccount.PrevFallbackKey)
	assert.Equal(t, firstAccount.OTKeys, unpickledAccount.OTKeys)
	assert.Equal(t, firstAccount.IdKeys, unpickledAccount.IdKeys)

	// Ensure that all of the keys are unpublished right now
	otks, err := firstAccount.OneTimeKeys()
	assert.NoError(t, err)
	assert.Len(t, otks, 2)
	assert.Len(t, firstAccount.FallbackKeyUnpublished(), 1)

	// Now, publish the key and make sure that they are published
	firstAccount.MarkKeysAsPublished()

	assert.Len(t, firstAccount.FallbackKeyUnpublished(), 0)
	assert.Len(t, firstAccount.FallbackKey(), 1)
	otks, err = firstAccount.OneTimeKeys()
	assert.NoError(t, err)
	assert.Len(t, otks, 0)
}

func TestAccountPickleJSON(t *testing.T) {
	key := []byte("test key")

	/*
		// Generating new values when struct changed
		newAccount, _ := NewAccount()
		pickled, _ := newAccount.PickleAsJSON(key)
		fmt.Println(string(pickled))
		jsonDataNew, _ := newAccount.IdentityKeysJSON()
		fmt.Println(string(jsonDataNew))
		return
	*/

	pickledData := []byte("6POkBWwbNl20fwvZWsOu0jgbHy4jkA5h0Ji+XCag59+ifWIRPDrqtgQi9HmkLiSF6wUhhYaV4S73WM+Hh+dlCuZRuXhTQr8yGPTifjcjq8birdAhObbEqHrYEdqaQkrgBLr/rlS5sibXeDqbkhVu4LslvootU9DkcCbd4b/0Flh7iugxqkcCs5GDndTEx9IzTVJzmK82Y0Q1Z1Z9Vuc2Iw746PtBJLtZjite6fSMp2NigPX/ZWWJ3OnwcJo0Vvjy8hgptZEWkamOHdWbUtelbHyjDIZlvxOC25D3rFif0zzPkF9qdpBPqVCWPPzGFmgnqKau6CHrnPfq7GLsM3BrprD7sHN1Js28ex14gXQPjBT7KTUo6H0e4gQMTMRp4qb8btNXDeId8xIFIElTh2SXZBTDmSq/ziVNJinEvYV8mGPvJZjDQQU+SyoS/HZ8uMc41tH0BOGDbFMHbfLMiz61E429gOrx2klu5lqyoyet7//HKi0ed5w2dQ")
	account, err := account.AccountFromJSONPickled(pickledData, key)
	assert.NoError(t, err)
	expectedJSON := `{"ed25519":"qWvNB6Ztov5/AOsP073op0O32KJ8/tgSNarT7MaYgQE","curve25519":"TFUB6M6zwgyWhBEp2m1aUodl2AsnsrIuBr8l9AvwGS8"}`
	jsonData, err := account.IdentityKeysJSON()
	assert.NoError(t, err)
	assert.Equal(t, expectedJSON, string(jsonData))
}

func TestSessions(t *testing.T) {
	aliceAccount, err := account.NewAccount()
	assert.NoError(t, err)
	err = aliceAccount.GenOneTimeKeys(5)
	assert.NoError(t, err)
	bobAccount, err := account.NewAccount()
	assert.NoError(t, err)
	err = bobAccount.GenOneTimeKeys(5)
	assert.NoError(t, err)
	aliceSession, err := aliceAccount.NewOutboundSession(bobAccount.IdKeys.Curve25519.B64Encoded(), bobAccount.OTKeys[2].Key.B64Encoded())
	assert.NoError(t, err)
	plaintext := []byte("test message")
	msgType, crypttext, err := aliceSession.Encrypt(plaintext)
	assert.NoError(t, err)
	assert.Equal(t, id.OlmMsgTypePreKey, msgType)

	bobSession, err := bobAccount.NewInboundSession(string(crypttext))
	assert.NoError(t, err)
	decodedText, err := bobSession.Decrypt(string(crypttext), msgType)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decodedText)
}

func TestAccountPickle(t *testing.T) {
	pickleKey := []byte("secret_key")
	account, err := account.AccountFromPickled(pickledDataFromLibOlm, pickleKey)
	assert.NoError(t, err)
	assert.Equal(t, expectedEd25519KeyPairPickleLibOLM, account.IdKeys.Ed25519)
	assert.Equal(t, expectedCurve25519KeyPairPickleLibOLM, account.IdKeys.Curve25519)
	assert.EqualValues(t, 42, account.NextOneTimeKeyID)
	assert.Equal(t, account.OTKeys, expectedOTKeysPickleLibOLM)
	assert.EqualValues(t, 0, account.NumFallbackKeys)

	targetPickled, err := account.Pickle(pickleKey)
	assert.NoError(t, err)
	assert.Equal(t, pickledDataFromLibOlm, targetPickled)
}

func TestOldAccountPickle(t *testing.T) {
	// this uses the old pickle format, which did not use enough space
	// for the Ed25519 key. We should reject it.
	pickled := []byte("x3h9er86ygvq56pM1yesdAxZou4ResPQC9Rszk/fhEL9JY/umtZ2N/foL/SUgVXS" +
		"v0IxHHZTafYjDdzJU9xr8dQeBoOTGfV9E/lCqDGBnIlu7SZndqjEKXtzGyQr4sP4" +
		"K/A/8TOu9iK2hDFszy6xETiousHnHgh2ZGbRUh4pQx+YMm8ZdNZeRnwFGLnrWyf9" +
		"O5TmXua1FcU")
	pickleKey := []byte("")
	account, err := account.NewAccount()
	assert.NoError(t, err)
	err = account.Unpickle(pickled, pickleKey)
	assert.ErrorIs(t, err, olm.ErrBadVersion)
}

func TestLoopback(t *testing.T) {
	accountA, err := account.NewAccount()
	assert.NoError(t, err)

	accountB, err := account.NewAccount()
	assert.NoError(t, err)
	err = accountB.GenOneTimeKeys(42)
	assert.NoError(t, err)

	aliceSession, err := accountA.NewOutboundSession(accountB.IdKeys.Curve25519.B64Encoded(), accountB.OTKeys[0].Key.B64Encoded())
	assert.NoError(t, err)

	plainText := []byte("Hello, World")
	msgType, message1, err := aliceSession.Encrypt(plainText)
	assert.NoError(t, err)
	assert.Equal(t, id.OlmMsgTypePreKey, msgType)

	bobSession, err := accountB.NewInboundSession(string(message1))
	assert.NoError(t, err)
	// Check that the inbound session matches the message it was created from.
	sessionIsOK, err := bobSession.MatchesInboundSessionFrom("", string(message1))
	assert.NoError(t, err)
	assert.True(t, sessionIsOK, "session was not detected to be valid")

	// Check that the inbound session matches the key this message is supposed to be from.
	aIDKey := accountA.IdKeys.Curve25519.PublicKey.B64Encoded()
	sessionIsOK, err = bobSession.MatchesInboundSessionFrom(string(aIDKey), string(message1))
	assert.NoError(t, err)
	assert.True(t, sessionIsOK, "session is sad to be not from a but it should")

	// Check that the inbound session isn't from a different user.
	bIDKey := accountB.IdKeys.Curve25519.PublicKey.B64Encoded()
	sessionIsOK, err = bobSession.MatchesInboundSessionFrom(string(bIDKey), string(message1))
	assert.NoError(t, err)
	assert.False(t, sessionIsOK, "session is sad to be from b but is from a")

	// Check that we can decrypt the message.
	decryptedMessage, err := bobSession.Decrypt(string(message1), msgType)
	assert.NoError(t, err)
	assert.Equal(t, plainText, decryptedMessage)

	msgTyp2, message2, err := bobSession.Encrypt(plainText)
	assert.NoError(t, err)
	assert.Equal(t, id.OlmMsgTypeMsg, msgTyp2)

	decryptedMessage2, err := aliceSession.Decrypt(string(message2), msgTyp2)
	assert.NoError(t, err)
	assert.Equal(t, plainText, decryptedMessage2)

	//decrypting again should fail, as the chain moved on
	_, err = aliceSession.Decrypt(string(message2), msgTyp2)
	assert.Error(t, err)
	assert.ErrorIs(t, err, olm.ErrMessageKeyNotFound)

	//compare sessionIDs
	assert.Equal(t, aliceSession.ID(), bobSession.ID())
}

func TestMoreMessages(t *testing.T) {
	accountA, err := account.NewAccount()
	assert.NoError(t, err)

	accountB, err := account.NewAccount()
	assert.NoError(t, err)
	err = accountB.GenOneTimeKeys(42)
	assert.NoError(t, err)

	aliceSession, err := accountA.NewOutboundSession(accountB.IdKeys.Curve25519.B64Encoded(), accountB.OTKeys[0].Key.B64Encoded())
	assert.NoError(t, err)

	plainText := []byte("Hello, World")
	msgType, message1, err := aliceSession.Encrypt(plainText)
	assert.NoError(t, err)
	assert.Equal(t, id.OlmMsgTypePreKey, msgType)

	bobSession, err := accountB.NewInboundSession(string(message1))
	assert.NoError(t, err)
	decryptedMessage, err := bobSession.Decrypt(string(message1), msgType)
	assert.NoError(t, err)
	assert.Equal(t, plainText, decryptedMessage)

	for i := 0; i < 8; i++ {
		//alice sends, bob reveices
		msgType, message, err := aliceSession.Encrypt(plainText)
		assert.NoError(t, err)
		if i == 0 {
			//The first time should still be a preKeyMessage as bob has not yet send a message to alice
			assert.Equal(t, id.OlmMsgTypePreKey, msgType)
		} else {
			assert.Equal(t, id.OlmMsgTypeMsg, msgType)
		}

		decryptedMessage, err := bobSession.Decrypt(string(message), msgType)
		assert.NoError(t, err)
		assert.Equal(t, plainText, decryptedMessage)

		//now bob sends, alice receives
		msgType, message, err = bobSession.Encrypt(plainText)
		assert.NoError(t, err)
		assert.Equal(t, id.OlmMsgTypeMsg, msgType)

		decryptedMessage, err = aliceSession.Decrypt(string(message), msgType)
		assert.NoError(t, err)
		assert.Equal(t, plainText, decryptedMessage)
	}
}

func TestFallbackKey(t *testing.T) {
	accountA, err := account.NewAccount()
	assert.NoError(t, err)

	accountB, err := account.NewAccount()
	assert.NoError(t, err)
	err = accountB.GenFallbackKey()
	assert.NoError(t, err)
	fallBackKeys := accountB.FallbackKeyUnpublished()
	var fallbackKey id.Curve25519
	for _, fbKey := range fallBackKeys {
		fallbackKey = fbKey
	}
	aliceSession, err := accountA.NewOutboundSession(accountB.IdKeys.Curve25519.B64Encoded(), fallbackKey)
	assert.NoError(t, err)

	plainText := []byte("Hello, World")
	msgType, message1, err := aliceSession.Encrypt(plainText)
	assert.NoError(t, err)
	assert.Equal(t, id.OlmMsgTypePreKey, msgType)

	bobSession, err := accountB.NewInboundSession(string(message1))
	assert.NoError(t, err)
	// Check that the inbound session matches the message it was created from.
	sessionIsOK, err := bobSession.MatchesInboundSessionFrom("", string(message1))
	assert.NoError(t, err)
	assert.True(t, sessionIsOK, "session was not detected to be valid")

	// Check that the inbound session matches the key this message is supposed to be from.
	aIDKey := accountA.IdKeys.Curve25519.PublicKey.B64Encoded()
	sessionIsOK, err = bobSession.MatchesInboundSessionFrom(string(aIDKey), string(message1))
	assert.NoError(t, err)
	assert.True(t, sessionIsOK, "session is sad to be not from a but it should")

	// Check that the inbound session isn't from a different user.
	bIDKey := accountB.IdKeys.Curve25519.PublicKey.B64Encoded()
	sessionIsOK, err = bobSession.MatchesInboundSessionFrom(string(bIDKey), string(message1))
	assert.NoError(t, err)
	assert.False(t, sessionIsOK, "session is sad to be from b but is from a")

	// Check that we can decrypt the message.
	decryptedMessage, err := bobSession.Decrypt(string(message1), msgType)
	assert.NoError(t, err)
	assert.Equal(t, plainText, decryptedMessage)

	// create a new fallback key for B (the old fallback should still be usable)
	err = accountB.GenFallbackKey()
	assert.NoError(t, err)
	// start another session and encrypt a message
	aliceSession2, err := accountA.NewOutboundSession(accountB.IdKeys.Curve25519.B64Encoded(), fallbackKey)
	assert.NoError(t, err)

	msgType2, message2, err := aliceSession2.Encrypt(plainText)
	assert.NoError(t, err)
	assert.Equal(t, id.OlmMsgTypePreKey, msgType2)

	// bobSession should not be valid for the message2
	// Check that the inbound session matches the message it was created from.
	sessionIsOK, err = bobSession.MatchesInboundSessionFrom("", string(message2))
	assert.NoError(t, err)
	assert.False(t, sessionIsOK, "session was detected to be valid but should not")

	bobSession2, err := accountB.NewInboundSession(string(message2))
	assert.NoError(t, err)
	// Check that the inbound session matches the message it was created from.
	sessionIsOK, err = bobSession2.MatchesInboundSessionFrom("", string(message2))
	assert.NoError(t, err)
	assert.True(t, sessionIsOK, "session was not detected to be valid")

	// Check that the inbound session matches the key this message is supposed to be from.
	sessionIsOK, err = bobSession2.MatchesInboundSessionFrom(string(aIDKey), string(message2))
	assert.NoError(t, err)
	assert.True(t, sessionIsOK, "session is sad to be not from a but it should")

	// Check that the inbound session isn't from a different user.
	sessionIsOK, err = bobSession2.MatchesInboundSessionFrom(string(bIDKey), string(message2))
	assert.NoError(t, err)
	assert.False(t, sessionIsOK, "session is sad to be from b but is from a")

	// Check that we can decrypt the message.
	decryptedMessage2, err := bobSession2.Decrypt(string(message2), msgType2)
	assert.NoError(t, err)
	assert.Equal(t, plainText, decryptedMessage2)

	//Forget the old fallback key -- creating a new session should fail now
	accountB.ForgetOldFallbackKey()
	// start another session and encrypt a message
	aliceSession3, err := accountA.NewOutboundSession(accountB.IdKeys.Curve25519.B64Encoded(), fallbackKey)
	assert.NoError(t, err)
	msgType3, message3, err := aliceSession3.Encrypt(plainText)
	assert.NoError(t, err)
	assert.Equal(t, id.OlmMsgTypePreKey, msgType3)
	_, err = accountB.NewInboundSession(string(message3))
	assert.ErrorIs(t, err, olm.ErrBadMessageKeyID)
}

func TestOldV3AccountPickle(t *testing.T) {
	pickledData := []byte("0mSqVn3duHffbhaTbFgW+4JPlcRoqT7z0x4mQ72N+g+eSAk5sgcWSoDzKpMazgcB" +
		"46ItEpChthVHTGRA6PD3dly0dUs4ji7VtWTa+1tUv1UbxP92uYf1Ae3fomX0yAoH" +
		"OjSrz1+RmuXr+At8jsmsf260sKvhB6LnI3qYsrw6AAtpgk5d5xZd66sLxvvYUuai" +
		"+SmmcmT0bHosLTuDiiB9amBvPKkUKtKZmaEAl5ULrgnJygp1/FnwzVfSrw6PBSX6" +
		"ZaUEZHZGX1iI6/WjbHqlTQeOQjtaSsPaL5XXpteS9dFsuaANAj+8ks7Ut2Hwg/JP" +
		"Ih/ERYBwiMh9Mt3zSAG0NkvgUkcdipKxoSNZ6t+TkqZrN6jG6VCbx+4YpJO24iJb" +
		"ShZy8n79aePIgIsxX94ycsTq1ic38sCRSkWGVbCSRkPloHW7ZssLHA")
	pickleKey := []byte("")
	expectedFallbackJSON := []byte("{\"curve25519\":{\"AAAAAQ\":\"dr98y6VOWt6lJaQgFVZeWY2ky76mga9MEMbdItJTdng\"}}")
	expectedUnpublishedFallbackJSON := []byte("{\"curve25519\":{}}")

	account, err := account.AccountFromPickled(pickledData, pickleKey)
	assert.NoError(t, err)
	fallbackJSON, err := account.FallbackKeyJSON()
	assert.NoError(t, err)
	assert.Equal(t, expectedFallbackJSON, fallbackJSON)
	fallbackJSONUnpublished, err := account.FallbackKeyUnpublishedJSON()
	assert.NoError(t, err)
	assert.Equal(t, expectedUnpublishedFallbackJSON, fallbackJSONUnpublished)
}

func TestAccountSign(t *testing.T) {
	accountA, err := account.NewAccount()
	assert.NoError(t, err)
	plainText := []byte("Hello, World")
	signatureB64, err := accountA.Sign(plainText)
	assert.NoError(t, err)
	signature, err := base64.RawStdEncoding.DecodeString(string(signatureB64))
	assert.NoError(t, err)

	verified, err := signatures.VerifySignature(plainText, accountA.IdKeys.Ed25519.B64Encoded(), signature)
	assert.NoError(t, err)
	assert.True(t, verified)
}
