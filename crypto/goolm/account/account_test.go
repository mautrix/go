package account_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/element-hq/mautrix-go/id"

	"github.com/element-hq/mautrix-go/crypto/goolm"
	"github.com/element-hq/mautrix-go/crypto/goolm/account"
	"github.com/element-hq/mautrix-go/crypto/signatures"
)

func TestAccount(t *testing.T) {
	firstAccount, err := account.NewAccount(nil)
	if err != nil {
		t.Fatal(err)
	}
	err = firstAccount.GenFallbackKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	err = firstAccount.GenOneTimeKeys(nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	encryptionKey := []byte("testkey")
	//now pickle account in JSON format
	pickled, err := firstAccount.PickleAsJSON(encryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	//now unpickle into new Account
	unpickledAccount, err := account.AccountFromJSONPickled(pickled, encryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	//check if accounts are the same
	if firstAccount.NextOneTimeKeyID != unpickledAccount.NextOneTimeKeyID {
		t.Fatal("NextOneTimeKeyID unequal")
	}
	if !firstAccount.CurrentFallbackKey.Equal(unpickledAccount.CurrentFallbackKey) {
		t.Fatal("CurrentFallbackKey unequal")
	}
	if !firstAccount.PrevFallbackKey.Equal(unpickledAccount.PrevFallbackKey) {
		t.Fatal("PrevFallbackKey unequal")
	}
	if len(firstAccount.OTKeys) != len(unpickledAccount.OTKeys) {
		t.Fatal("OneTimeKeysunequal")
	}
	for i := range firstAccount.OTKeys {
		if !firstAccount.OTKeys[i].Equal(unpickledAccount.OTKeys[i]) {
			t.Fatalf("OneTimeKeys %d unequal", i)
		}
	}
	if !firstAccount.IdKeys.Curve25519.PrivateKey.Equal(unpickledAccount.IdKeys.Curve25519.PrivateKey) {
		t.Fatal("IdentityKeys Curve25519 private unequal")
	}
	if !firstAccount.IdKeys.Curve25519.PublicKey.Equal(unpickledAccount.IdKeys.Curve25519.PublicKey) {
		t.Fatal("IdentityKeys Curve25519 public unequal")
	}
	if !firstAccount.IdKeys.Ed25519.PrivateKey.Equal(unpickledAccount.IdKeys.Ed25519.PrivateKey) {
		t.Fatal("IdentityKeys Ed25519 private unequal")
	}
	if !firstAccount.IdKeys.Ed25519.PublicKey.Equal(unpickledAccount.IdKeys.Ed25519.PublicKey) {
		t.Fatal("IdentityKeys Ed25519 public unequal")
	}

	if len(firstAccount.OneTimeKeys()) != 2 {
		t.Fatal("should get 2 unpublished oneTimeKeys")
	}
	if len(firstAccount.FallbackKeyUnpublished()) == 0 {
		t.Fatal("should get fallbackKey")
	}
	firstAccount.MarkKeysAsPublished()
	if len(firstAccount.FallbackKey()) == 0 {
		t.Fatal("should get fallbackKey")
	}
	if len(firstAccount.FallbackKeyUnpublished()) != 0 {
		t.Fatal("should get no fallbackKey")
	}
	if len(firstAccount.OneTimeKeys()) != 0 {
		t.Fatal("should get no oneTimeKeys")
	}
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
	if err != nil {
		t.Fatal(err)
	}
	expectedJSON := `{"ed25519":"qWvNB6Ztov5/AOsP073op0O32KJ8/tgSNarT7MaYgQE","curve25519":"TFUB6M6zwgyWhBEp2m1aUodl2AsnsrIuBr8l9AvwGS8"}`
	jsonData, err := account.IdentityKeysJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(jsonData, []byte(expectedJSON)) {
		t.Fatalf("Expected '%s' but got '%s'", expectedJSON, jsonData)
	}
}

func TestSessions(t *testing.T) {
	aliceAccount, err := account.NewAccount(nil)
	if err != nil {
		t.Fatal(err)
	}
	err = aliceAccount.GenOneTimeKeys(nil, 5)
	if err != nil {
		t.Fatal(err)
	}
	bobAccount, err := account.NewAccount(nil)
	if err != nil {
		t.Fatal(err)
	}
	err = bobAccount.GenOneTimeKeys(nil, 5)
	if err != nil {
		t.Fatal(err)
	}
	aliceSession, err := aliceAccount.NewOutboundSession(bobAccount.IdKeys.Curve25519.B64Encoded(), bobAccount.OTKeys[2].Key.B64Encoded())
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("test message")
	msgType, crypttext, err := aliceSession.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatal(err)
	}
	if msgType != id.OlmMsgTypePreKey {
		t.Fatal("wrong message type")
	}

	bobSession, err := bobAccount.NewInboundSession(nil, crypttext)
	if err != nil {
		t.Fatal(err)
	}
	decodedText, err := bobSession.Decrypt(crypttext, msgType)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, decodedText) {
		t.Fatalf("expected '%s' but got '%s'", string(plaintext), string(decodedText))
	}
}

func TestAccountPickle(t *testing.T) {
	pickleKey := []byte("secret_key")
	account, err := account.AccountFromPickled(pickledDataFromLibOlm, pickleKey)
	if err != nil {
		t.Fatal(err)
	}
	if !expectedEd25519KeyPairPickleLibOLM.PrivateKey.Equal(account.IdKeys.Ed25519.PrivateKey) {
		t.Fatal("keys not equal")
	}
	if !expectedEd25519KeyPairPickleLibOLM.PublicKey.Equal(account.IdKeys.Ed25519.PublicKey) {
		t.Fatal("keys not equal")
	}
	if !expectedCurve25519KeyPairPickleLibOLM.PrivateKey.Equal(account.IdKeys.Curve25519.PrivateKey) {
		t.Fatal("keys not equal")
	}
	if !expectedCurve25519KeyPairPickleLibOLM.PublicKey.Equal(account.IdKeys.Curve25519.PublicKey) {
		t.Fatal("keys not equal")
	}
	if account.NextOneTimeKeyID != 42 {
		t.Fatal("wrong next otKey id")
	}
	if len(account.OTKeys) != len(expectedOTKeysPickleLibOLM) {
		t.Fatal("wrong number of otKeys")
	}
	if account.NumFallbackKeys != 0 {
		t.Fatal("fallback keys set but not in pickle")
	}
	for curIndex, curValue := range account.OTKeys {
		curExpected := expectedOTKeysPickleLibOLM[curIndex]
		if curExpected.ID != curValue.ID {
			t.Fatal("OTKey id not correct")
		}
		if !curExpected.Key.PublicKey.Equal(curValue.Key.PublicKey) {
			t.Fatal("OTKey public key not correct")
		}
		if !curExpected.Key.PrivateKey.Equal(curValue.Key.PrivateKey) {
			t.Fatal("OTKey private key not correct")
		}
	}

	targetPickled, err := account.Pickle(pickleKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(targetPickled, pickledDataFromLibOlm) {
		t.Fatal("repickled value does not equal given value")
	}
}

func TestOldAccountPickle(t *testing.T) {
	// this uses the old pickle format, which did not use enough space
	// for the Ed25519 key. We should reject it.
	pickled := []byte("x3h9er86ygvq56pM1yesdAxZou4ResPQC9Rszk/fhEL9JY/umtZ2N/foL/SUgVXS" +
		"v0IxHHZTafYjDdzJU9xr8dQeBoOTGfV9E/lCqDGBnIlu7SZndqjEKXtzGyQr4sP4" +
		"K/A/8TOu9iK2hDFszy6xETiousHnHgh2ZGbRUh4pQx+YMm8ZdNZeRnwFGLnrWyf9" +
		"O5TmXua1FcU")
	pickleKey := []byte("")
	account, err := account.NewAccount(nil)
	if err != nil {
		t.Fatal(err)
	}
	err = account.Unpickle(pickled, pickleKey)
	if err == nil {
		t.Fatal("expected error")
	} else {
		if !errors.Is(err, goolm.ErrBadVersion) {
			t.Fatal(err)
		}
	}
}

func TestLoopback(t *testing.T) {
	accountA, err := account.NewAccount(nil)
	if err != nil {
		t.Fatal(err)
	}

	accountB, err := account.NewAccount(nil)
	if err != nil {
		t.Fatal(err)
	}
	err = accountB.GenOneTimeKeys(nil, 42)
	if err != nil {
		t.Fatal(err)
	}

	aliceSession, err := accountA.NewOutboundSession(accountB.IdKeys.Curve25519.B64Encoded(), accountB.OTKeys[0].Key.B64Encoded())
	if err != nil {
		t.Fatal(err)
	}

	plainText := []byte("Hello, World")
	msgType, message1, err := aliceSession.Encrypt(plainText, nil)
	if err != nil {
		t.Fatal(err)
	}
	if msgType != id.OlmMsgTypePreKey {
		t.Fatal("wrong message type")
	}

	bobSession, err := accountB.NewInboundSession(nil, message1)
	if err != nil {
		t.Fatal(err)
	}
	// Check that the inbound session matches the message it was created from.
	sessionIsOK, err := bobSession.MatchesInboundSessionFrom(nil, message1)
	if err != nil {
		t.Fatal(err)
	}
	if !sessionIsOK {
		t.Fatal("session was not detected to be valid")
	}
	// Check that the inbound session matches the key this message is supposed to be from.
	aIDKey := accountA.IdKeys.Curve25519.PublicKey.B64Encoded()
	sessionIsOK, err = bobSession.MatchesInboundSessionFrom(&aIDKey, message1)
	if err != nil {
		t.Fatal(err)
	}
	if !sessionIsOK {
		t.Fatal("session is sad to be not from a but it should")
	}
	// Check that the inbound session isn't from a different user.
	bIDKey := accountB.IdKeys.Curve25519.PublicKey.B64Encoded()
	sessionIsOK, err = bobSession.MatchesInboundSessionFrom(&bIDKey, message1)
	if err != nil {
		t.Fatal(err)
	}
	if sessionIsOK {
		t.Fatal("session is sad to be from b but is from a")
	}
	// Check that we can decrypt the message.
	decryptedMessage, err := bobSession.Decrypt(message1, msgType)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decryptedMessage, plainText) {
		t.Fatal("messages are not the same")
	}

	msgTyp2, message2, err := bobSession.Encrypt(plainText, nil)
	if err != nil {
		t.Fatal(err)
	}
	if msgTyp2 == id.OlmMsgTypePreKey {
		t.Fatal("wrong message type")
	}

	decryptedMessage2, err := aliceSession.Decrypt(message2, msgTyp2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decryptedMessage2, plainText) {
		t.Fatal("messages are not the same")
	}

	//decrypting again should fail, as the chain moved on
	_, err = aliceSession.Decrypt(message2, msgTyp2)
	if err == nil {
		t.Fatal("expected error")
	}

	//compare sessionIDs
	if aliceSession.ID() != bobSession.ID() {
		t.Fatal("sessionIDs are not equal")
	}
}

func TestMoreMessages(t *testing.T) {
	accountA, err := account.NewAccount(nil)
	if err != nil {
		t.Fatal(err)
	}

	accountB, err := account.NewAccount(nil)
	if err != nil {
		t.Fatal(err)
	}
	err = accountB.GenOneTimeKeys(nil, 42)
	if err != nil {
		t.Fatal(err)
	}

	aliceSession, err := accountA.NewOutboundSession(accountB.IdKeys.Curve25519.B64Encoded(), accountB.OTKeys[0].Key.B64Encoded())
	if err != nil {
		t.Fatal(err)
	}

	plainText := []byte("Hello, World")
	msgType, message1, err := aliceSession.Encrypt(plainText, nil)
	if err != nil {
		t.Fatal(err)
	}
	if msgType != id.OlmMsgTypePreKey {
		t.Fatal("wrong message type")
	}

	bobSession, err := accountB.NewInboundSession(nil, message1)
	if err != nil {
		t.Fatal(err)
	}
	decryptedMessage, err := bobSession.Decrypt(message1, msgType)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decryptedMessage, plainText) {
		t.Fatal("messages are not the same")
	}

	for i := 0; i < 8; i++ {
		//alice sends, bob reveices
		msgType, message, err := aliceSession.Encrypt(plainText, nil)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			//The first time should still be a preKeyMessage as bob has not yet send a message to alice
			if msgType != id.OlmMsgTypePreKey {
				t.Fatal("wrong message type")
			}
		} else {
			if msgType == id.OlmMsgTypePreKey {
				t.Fatal("wrong message type")
			}
		}
		decryptedMessage, err := bobSession.Decrypt(message, msgType)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decryptedMessage, plainText) {
			t.Fatal("messages are not the same")
		}

		//now bob sends, alice receives
		msgType, message, err = bobSession.Encrypt(plainText, nil)
		if err != nil {
			t.Fatal(err)
		}
		if msgType == id.OlmMsgTypePreKey {
			t.Fatal("wrong message type")
		}
		decryptedMessage, err = aliceSession.Decrypt(message, msgType)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decryptedMessage, plainText) {
			t.Fatal("messages are not the same")
		}
	}
}

func TestFallbackKey(t *testing.T) {
	accountA, err := account.NewAccount(nil)
	if err != nil {
		t.Fatal(err)
	}

	accountB, err := account.NewAccount(nil)
	if err != nil {
		t.Fatal(err)
	}
	err = accountB.GenFallbackKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	fallBackKeys := accountB.FallbackKeyUnpublished()
	var fallbackKey id.Curve25519
	for _, fbKey := range fallBackKeys {
		fallbackKey = fbKey
	}
	aliceSession, err := accountA.NewOutboundSession(accountB.IdKeys.Curve25519.B64Encoded(), fallbackKey)
	if err != nil {
		t.Fatal(err)
	}

	plainText := []byte("Hello, World")
	msgType, message1, err := aliceSession.Encrypt(plainText, nil)
	if err != nil {
		t.Fatal(err)
	}
	if msgType != id.OlmMsgTypePreKey {
		t.Fatal("wrong message type")
	}

	bobSession, err := accountB.NewInboundSession(nil, message1)
	if err != nil {
		t.Fatal(err)
	}
	// Check that the inbound session matches the message it was created from.
	sessionIsOK, err := bobSession.MatchesInboundSessionFrom(nil, message1)
	if err != nil {
		t.Fatal(err)
	}
	if !sessionIsOK {
		t.Fatal("session was not detected to be valid")
	}
	// Check that the inbound session matches the key this message is supposed to be from.
	aIDKey := accountA.IdKeys.Curve25519.PublicKey.B64Encoded()
	sessionIsOK, err = bobSession.MatchesInboundSessionFrom(&aIDKey, message1)
	if err != nil {
		t.Fatal(err)
	}
	if !sessionIsOK {
		t.Fatal("session is sad to be not from a but it should")
	}
	// Check that the inbound session isn't from a different user.
	bIDKey := accountB.IdKeys.Curve25519.PublicKey.B64Encoded()
	sessionIsOK, err = bobSession.MatchesInboundSessionFrom(&bIDKey, message1)
	if err != nil {
		t.Fatal(err)
	}
	if sessionIsOK {
		t.Fatal("session is sad to be from b but is from a")
	}
	// Check that we can decrypt the message.
	decryptedMessage, err := bobSession.Decrypt(message1, msgType)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decryptedMessage, plainText) {
		t.Fatal("messages are not the same")
	}

	// create a new fallback key for B (the old fallback should still be usable)
	err = accountB.GenFallbackKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	// start another session and encrypt a message
	aliceSession2, err := accountA.NewOutboundSession(accountB.IdKeys.Curve25519.B64Encoded(), fallbackKey)
	if err != nil {
		t.Fatal(err)
	}

	msgType2, message2, err := aliceSession2.Encrypt(plainText, nil)
	if err != nil {
		t.Fatal(err)
	}
	if msgType2 != id.OlmMsgTypePreKey {
		t.Fatal("wrong message type")
	}
	// bobSession should not be valid for the message2
	// Check that the inbound session matches the message it was created from.
	sessionIsOK, err = bobSession.MatchesInboundSessionFrom(nil, message2)
	if err != nil {
		t.Fatal(err)
	}
	if sessionIsOK {
		t.Fatal("session was detected to be valid but should not")
	}
	bobSession2, err := accountB.NewInboundSession(nil, message2)
	if err != nil {
		t.Fatal(err)
	}
	// Check that the inbound session matches the message it was created from.
	sessionIsOK, err = bobSession2.MatchesInboundSessionFrom(nil, message2)
	if err != nil {
		t.Fatal(err)
	}
	if !sessionIsOK {
		t.Fatal("session was not detected to be valid")
	}
	// Check that the inbound session matches the key this message is supposed to be from.
	sessionIsOK, err = bobSession2.MatchesInboundSessionFrom(&aIDKey, message2)
	if err != nil {
		t.Fatal(err)
	}
	if !sessionIsOK {
		t.Fatal("session is sad to be not from a but it should")
	}
	// Check that the inbound session isn't from a different user.
	sessionIsOK, err = bobSession2.MatchesInboundSessionFrom(&bIDKey, message2)
	if err != nil {
		t.Fatal(err)
	}
	if sessionIsOK {
		t.Fatal("session is sad to be from b but is from a")
	}
	// Check that we can decrypt the message.
	decryptedMessage2, err := bobSession2.Decrypt(message2, msgType2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decryptedMessage2, plainText) {
		t.Fatal("messages are not the same")
	}

	//Forget the old fallback key -- creating a new session should fail now
	accountB.ForgetOldFallbackKey()
	// start another session and encrypt a message
	aliceSession3, err := accountA.NewOutboundSession(accountB.IdKeys.Curve25519.B64Encoded(), fallbackKey)
	if err != nil {
		t.Fatal(err)
	}
	msgType3, message3, err := aliceSession3.Encrypt(plainText, nil)
	if err != nil {
		t.Fatal(err)
	}
	if msgType3 != id.OlmMsgTypePreKey {
		t.Fatal("wrong message type")
	}
	_, err = accountB.NewInboundSession(nil, message3)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, goolm.ErrBadMessageKeyID) {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	fallbackJSON, err := account.FallbackKeyJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fallbackJSON, expectedFallbackJSON) {
		t.Fatalf("expected not as result:\n%s\n%s\n", expectedFallbackJSON, fallbackJSON)
	}
	fallbackJSONUnpublished, err := account.FallbackKeyUnpublishedJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fallbackJSONUnpublished, expectedUnpublishedFallbackJSON) {
		t.Fatalf("expected not as result:\n%s\n%s\n", expectedUnpublishedFallbackJSON, fallbackJSONUnpublished)
	}
}

func TestAccountSign(t *testing.T) {
	accountA, err := account.NewAccount(nil)
	require.NoError(t, err)
	plainText := []byte("Hello, World")
	signatureB64, err := accountA.Sign(plainText)
	require.NoError(t, err)
	signature, err := base64.RawStdEncoding.DecodeString(string(signatureB64))
	require.NoError(t, err)

	verified, err := signatures.VerifySignature(plainText, accountA.IdKeys.Ed25519.B64Encoded(), signature)
	assert.NoError(t, err)
	assert.True(t, verified)
}
