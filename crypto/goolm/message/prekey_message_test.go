package message_test

import (
	"bytes"
	"testing"

	"github.com/element-hq/mautrix-go/crypto/goolm/crypto"
	"github.com/element-hq/mautrix-go/crypto/goolm/message"
)

func TestPreKeyMessageDecode(t *testing.T) {
	//Keys are 32 bytes to pass field check
	//Added a tag for an integer of 0 just for checkes
	messageRaw := []byte("\x03\x0a\x20onetimeKey.-.-.-.-.-.-.-.-.-.-.-\x1a\x20idKeywithlendth32bytes-.-.-.-.-.\x12\x20baseKey-.-.-.-.-.-.-.-.-.-.-.-.-\x22\x07message\x00\x00")
	expectedOneTimeKey := []byte("onetimeKey.-.-.-.-.-.-.-.-.-.-.-")
	expectedIdKey := []byte("idKeywithlendth32bytes-.-.-.-.-.")
	expectedbaseKey := []byte("baseKey-.-.-.-.-.-.-.-.-.-.-.-.-")
	expectedmessage := []byte("message")

	msg := message.PreKeyMessage{}
	err := msg.Decode(messageRaw)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Version != 3 {
		t.Fatalf("Expected Version to be 3 but go %d", msg.Version)
	}
	if !bytes.Equal(msg.OneTimeKey, expectedOneTimeKey) {
		t.Fatalf("expected '%s' but got '%s'", expectedOneTimeKey, msg.OneTimeKey)
	}
	if !bytes.Equal(msg.IdentityKey, expectedIdKey) {
		t.Fatalf("expected '%s' but got '%s'", expectedIdKey, msg.IdentityKey)
	}
	if !bytes.Equal(msg.BaseKey, expectedbaseKey) {
		t.Fatalf("expected '%s' but got '%s'", expectedbaseKey, msg.BaseKey)
	}
	if !bytes.Equal(msg.Message, expectedmessage) {
		t.Fatalf("expected '%s' but got '%s'", expectedmessage, msg.Message)
	}
	theirIDKey := crypto.Curve25519PublicKey(expectedIdKey)
	checked := msg.CheckFields(&theirIDKey)
	if !checked {
		t.Fatal("field check failed")
	}
}

func TestPreKeyMessageEncode(t *testing.T) {
	expectedRaw := []byte("\x03\x0a\x0aonetimeKey\x1a\x05idKey\x12\x07baseKey\x22\x07message")
	msg := message.PreKeyMessage{
		Version:     3,
		IdentityKey: []byte("idKey"),
		BaseKey:     []byte("baseKey"),
		OneTimeKey:  []byte("onetimeKey"),
		Message:     []byte("message"),
	}
	encoded, err := msg.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, expectedRaw) {
		t.Fatalf("got other than expected:\nExpected:\n%v\nGot:\n%v", expectedRaw, encoded)
	}
}
