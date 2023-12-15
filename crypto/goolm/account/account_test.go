package account

import (
	"bytes"
	"errors"
	"testing"

	"codeberg.org/DerLukas/goolm"
	"codeberg.org/DerLukas/goolm/utilities"
	"maunium.net/go/mautrix/id"
)

type mockRandom struct {
	tag     byte
	current byte
}

func (m *mockRandom) get(length int) []byte {
	res := make([]byte, length)
	baseIndex := 0
	for length > 32 {
		res[baseIndex] = m.tag
		for i := 1; i < 32; i++ {
			res[baseIndex+i] = m.current
		}
		length -= 32
		baseIndex += 32
		m.current++
	}
	if length != 0 {
		res[baseIndex] = m.tag
		for i := 1; i < length-1; i++ {
			res[baseIndex+i] = m.current
		}
		m.current++
	}
	return res
}

func (m *mockRandom) Read(target []byte) (int, error) {
	res := m.get(len(target))
	return copy(target, res), nil
}

func TestAccount(t *testing.T) {
	firstAccount, err := NewAccount(nil)
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
	unpickledAccount, err := AccountFromJSONPickled(pickled, encryptionKey)
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

	pickledData := []byte("fZG5DhZ0+uhVFEcdgo/dyWNy1BlSKo+W18D/QLBcZfvP0rByRzjgJM5yeDIO9N6jYFp2MbV1Y1DikFlDctwq7PhIRvbtLdrzxT94WoLrUdiNtQkw6NRNXvsFYo4NKoAgl1yQauttnGRBHCCPVV6e9d4kvnPVRkZNkbbANnadF0Tld/SMMWWoPI3L7dy+oiRh6nqNKvZz+upvgmOSm6gu2xV0yx9RJpkvLz8oHMDui1VQ1T2wTpfk5vdw0Cx4BXspf8WDnntdv0Ui4qBzUFmsB4lfqLviuhnAxu+qQrrKcZz/EyzbPwmI+P4Tn5KznxzEx2Nw/AjKKPxqVAKpx8+nV7rKKzlah71wX2CHyEsp2ptcNTJ1lr6tJxkOLdy8Rw285jpKw4MrgghnhqZ9Hh3y5P6KnRrq6zom9zfkCtCXs2h8BK+I0tkMPXO+JZoJKVOWzS+n7FIrC9XC9nAu19G5cnxv+tJdPb3p")
	account, err := AccountFromJSONPickled(pickledData, key)
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
	aliceAccount, err := NewAccount(nil)
	if err != nil {
		t.Fatal(err)
	}
	err = aliceAccount.GenOneTimeKeys(nil, 5)
	if err != nil {
		t.Fatal(err)
	}
	bobAccount, err := NewAccount(nil)
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
	account, err := AccountFromPickled(pickledDataFromLibOlm, pickleKey)
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
	account, err := NewAccount(nil)
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
	mockA := mockRandom{
		tag:     []byte("A")[0],
		current: 0x00,
	}
	mockB := mockRandom{
		tag:     []byte("B")[0],
		current: 0x80,
	}
	accountA, err := NewAccount(&mockA)
	if err != nil {
		t.Fatal(err)
	}

	accountB, err := NewAccount(&mockB)
	if err != nil {
		t.Fatal(err)
	}
	err = accountB.GenOneTimeKeys(&mockB, 42)
	if err != nil {
		t.Fatal(err)
	}

	aliceSession, err := accountA.NewOutboundSession(accountB.IdKeys.Curve25519.B64Encoded(), accountB.OTKeys[0].Key.B64Encoded())
	if err != nil {
		t.Fatal(err)
	}

	plainText := []byte("Hello, World")
	msgType, message1, err := aliceSession.Encrypt(plainText, &mockA)
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

	msgTyp2, message2, err := bobSession.Encrypt(plainText, &mockB)
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
	mockA := mockRandom{
		tag:     []byte("A")[0],
		current: 0x00,
	}
	mockB := mockRandom{
		tag:     []byte("B")[0],
		current: 0x80,
	}
	accountA, err := NewAccount(&mockA)
	if err != nil {
		t.Fatal(err)
	}

	accountB, err := NewAccount(&mockB)
	if err != nil {
		t.Fatal(err)
	}
	err = accountB.GenOneTimeKeys(&mockB, 42)
	if err != nil {
		t.Fatal(err)
	}

	aliceSession, err := accountA.NewOutboundSession(accountB.IdKeys.Curve25519.B64Encoded(), accountB.OTKeys[0].Key.B64Encoded())
	if err != nil {
		t.Fatal(err)
	}

	plainText := []byte("Hello, World")
	msgType, message1, err := aliceSession.Encrypt(plainText, &mockA)
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
		msgType, message, err := aliceSession.Encrypt(plainText, &mockA)
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
		msgType, message, err = bobSession.Encrypt(plainText, &mockA)
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
	mockA := mockRandom{
		tag:     []byte("A")[0],
		current: 0x00,
	}
	mockB := mockRandom{
		tag:     []byte("B")[0],
		current: 0x80,
	}
	accountA, err := NewAccount(&mockA)
	if err != nil {
		t.Fatal(err)
	}

	accountB, err := NewAccount(&mockB)
	if err != nil {
		t.Fatal(err)
	}
	err = accountB.GenFallbackKey(&mockB)
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
	msgType, message1, err := aliceSession.Encrypt(plainText, &mockA)
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
	err = accountB.GenFallbackKey(&mockB)
	if err != nil {
		t.Fatal(err)
	}
	// start another session and encrypt a message
	aliceSession2, err := accountA.NewOutboundSession(accountB.IdKeys.Curve25519.B64Encoded(), fallbackKey)
	if err != nil {
		t.Fatal(err)
	}

	msgType2, message2, err := aliceSession2.Encrypt(plainText, &mockA)
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
	msgType3, message3, err := aliceSession3.Encrypt(plainText, &mockA)
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

	account, err := AccountFromPickled(pickledData, pickleKey)
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
	mockA := mockRandom{
		tag:     []byte("A")[0],
		current: 0x00,
	}
	accountA, err := NewAccount(&mockA)
	if err != nil {
		t.Fatal(err)
	}
	plainText := []byte("Hello, World")
	signature, err := accountA.Sign(plainText)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := utilities.VerifySignature(plainText, accountA.IdKeys.Ed25519.B64Encoded(), signature)
	if err != nil {
		t.Fatal(err)
	}
	if !verified {
		t.Fatal("signature did not verify")
	}
}
