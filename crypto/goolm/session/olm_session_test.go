package session_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/element-hq/mautrix-go/crypto/goolm"
	"github.com/element-hq/mautrix-go/crypto/goolm/crypto"
	"github.com/element-hq/mautrix-go/crypto/goolm/session"
	"github.com/element-hq/mautrix-go/id"
)

func TestOlmSession(t *testing.T) {
	pickleKey := []byte("secretKey")
	aliceKeyPair, err := crypto.Curve25519GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	bobKeyPair, err := crypto.Curve25519GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	bobOneTimeKey, err := crypto.Curve25519GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	aliceSession, err := session.NewOutboundOlmSession(aliceKeyPair, bobKeyPair.PublicKey, bobOneTimeKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	//create a message so that there are more keys to marshal
	plaintext := []byte("Test message from Alice to Bob")
	msgType, message, err := aliceSession.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatal(err)
	}
	if msgType != id.OlmMsgTypePreKey {
		t.Fatal("Wrong message type")
	}

	searchFunc := func(target crypto.Curve25519PublicKey) *crypto.OneTimeKey {
		if target.Equal(bobOneTimeKey.PublicKey) {
			return &crypto.OneTimeKey{
				Key:       bobOneTimeKey,
				Published: false,
				ID:        1,
			}
		}
		return nil
	}
	//bob receives message
	bobSession, err := session.NewInboundOlmSession(nil, message, searchFunc, bobKeyPair)
	if err != nil {
		t.Fatal(err)
	}
	decryptedMsg, err := bobSession.Decrypt(message, msgType)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, decryptedMsg) {
		t.Fatalf("messages are not equal:\n%v\n%v\n", plaintext, decryptedMsg)
	}

	// Alice pickles session
	pickled, err := aliceSession.PickleAsJSON(pickleKey)
	if err != nil {
		t.Fatal(err)
	}

	//bob sends a message
	plaintext = []byte("A message from Bob to Alice")
	msgType, message, err = bobSession.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatal(err)
	}
	if msgType != id.OlmMsgTypeMsg {
		t.Fatal("Wrong message type")
	}

	//Alice unpickles session
	newAliceSession, err := session.OlmSessionFromJSONPickled(pickled, pickleKey)
	if err != nil {
		t.Fatal(err)
	}

	//Alice receives message
	decryptedMsg, err = newAliceSession.Decrypt(message, msgType)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, decryptedMsg) {
		t.Fatalf("messages are not equal:\n%v\n%v\n", plaintext, decryptedMsg)
	}

	//Alice receives message again
	_, err = newAliceSession.Decrypt(message, msgType)
	if err == nil {
		t.Fatal("should have gotten an error")
	}

	//Alice sends another message
	plaintext = []byte("A second message to Bob")
	msgType, message, err = newAliceSession.Encrypt(plaintext, nil)
	if err != nil {
		t.Fatal(err)
	}
	if msgType != id.OlmMsgTypeMsg {
		t.Fatal("Wrong message type")
	}
	//bob receives message
	decryptedMsg, err = bobSession.Decrypt(message, msgType)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, decryptedMsg) {
		t.Fatalf("messages are not equal:\n%v\n%v\n", plaintext, decryptedMsg)
	}
}

func TestSessionPickle(t *testing.T) {
	pickledDataFromLibOlm := []byte("icDKYm0b4aO23WgUuOxdpPoxC0UlEOYPVeuduNH3IkpFsmnWx5KuEOpxGiZw5IuB/sSn2RZUCTiJ90IvgC7AClkYGHep9O8lpiqQX73XVKD9okZDCAkBc83eEq0DKYC7HBkGRAU/4T6QPIBBY3UK4QZwULLE/fLsi3j4YZBehMtnlsqgHK0q1bvX4cRznZItVKR4ro0O9EAk6LLxJtSnRu5elSUk7YXT")
	pickleKey := []byte("secret_key")
	sess, err := session.OlmSessionFromPickled(pickledDataFromLibOlm, pickleKey)
	if err != nil {
		t.Fatal(err)
	}
	newPickled, err := sess.Pickle(pickleKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pickledDataFromLibOlm, newPickled) {
		t.Fatal("pickled version does not equal libolm version")
	}
	pickledDataFromLibOlm = append(pickledDataFromLibOlm, []byte("a")...)
	_, err = session.OlmSessionFromPickled(pickledDataFromLibOlm, pickleKey)
	if err == nil {
		t.Fatal("should have gotten an error")
	}
}

func TestDecrypts(t *testing.T) {
	messages := [][]byte{
		{0x41, 0x77, 0x6F},
		{0x7f, 0xff, 0x6f, 0x01, 0x01, 0x34, 0x6d, 0x67, 0x12, 0x01},
		{0xee, 0x77, 0x6f, 0x41, 0x49, 0x6f, 0x67, 0x41, 0x77, 0x80, 0x41, 0x77, 0x77, 0x80, 0x41, 0x77, 0x6f, 0x67, 0x16, 0x67, 0x0a, 0x67, 0x7d, 0x6f, 0x67, 0x0a, 0x67, 0xc2, 0x67, 0x7d},
		{0xe9, 0xe9, 0xc9, 0xc1, 0xe9, 0xe9, 0xc9, 0xe9, 0xc9, 0xc1, 0xe9, 0xe9, 0xc9, 0xc1},
	}
	expectedErr := []error{
		goolm.ErrInputToSmall,
		// Why are these being tested 🤔
		base64.CorruptInputError(0),
		base64.CorruptInputError(0),
		base64.CorruptInputError(0),
	}
	sessionPickled := []byte("E0p44KO2y2pzp9FIjv0rud2wIvWDi2dx367kP4Fz/9JCMrH+aG369HGymkFtk0+PINTLB9lQRt" +
		"ohea5d7G/UXQx3r5y4IWuyh1xaRnojEZQ9a5HRZSNtvmZ9NY1f1gutYa4UtcZcbvczN8b/5Bqg" +
		"e16cPUH1v62JKLlhoAJwRkH1wU6fbyOudERg5gdXA971btR+Q2V8GKbVbO5fGKL5phmEPVXyMs" +
		"rfjLdzQrgjOTxN8Pf6iuP+WFPvfnR9lDmNCFxJUVAdLIMnLuAdxf1TGcS+zzCzEE8btIZ99mHF" +
		"dGvPXeH8qLeNZA")
	pickleKey := []byte("")
	sess, err := session.OlmSessionFromPickled(sessionPickled, pickleKey)
	if err != nil {
		t.Fatal(err)
	}
	for curIndex, curMessage := range messages {
		_, err := sess.Decrypt(curMessage, id.OlmMsgTypePreKey)
		if err != nil {
			if !errors.Is(err, expectedErr[curIndex]) {
				t.Fatal(err)
			}
		} else {
			t.Fatal("error expected")
		}
	}
}
