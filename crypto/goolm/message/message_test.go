package message_test

import (
	"bytes"
	"testing"

	"github.com/element-hq/mautrix-go/crypto/goolm/message"
)

func TestMessageDecode(t *testing.T) {
	messageRaw := []byte("\x03\x10\x01\n\nratchetkey\"\nciphertexthmacsha2")
	expectedRatchetKey := []byte("ratchetkey")
	expectedCipherText := []byte("ciphertext")

	msg := message.Message{}
	err := msg.Decode(messageRaw)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Version != 3 {
		t.Fatalf("Expected Version to be 3 but go %d", msg.Version)
	}
	if !msg.HasCounter {
		t.Fatal("Expected to have counter")
	}
	if msg.Counter != 1 {
		t.Fatalf("Expected counter to be 1 but got %d", msg.Counter)
	}
	if !bytes.Equal(msg.Ciphertext, expectedCipherText) {
		t.Fatalf("expected '%s' but got '%s'", expectedCipherText, msg.Ciphertext)
	}
	if !bytes.Equal(msg.RatchetKey, expectedRatchetKey) {
		t.Fatalf("expected '%s' but got '%s'", expectedRatchetKey, msg.RatchetKey)
	}
}

func TestMessageEncode(t *testing.T) {
	expectedRaw := []byte("\x03\n\nratchetkey\x10\x01\"\nciphertexthmacsha2")
	hmacsha256 := []byte("hmacsha2")
	msg := message.Message{
		Version:    3,
		Counter:    1,
		RatchetKey: []byte("ratchetkey"),
		Ciphertext: []byte("ciphertext"),
	}
	encoded, err := msg.EncodeAndMAC(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, hmacsha256...)
	if !bytes.Equal(encoded, expectedRaw) {
		t.Fatalf("expected '%s' but got '%s'", expectedRaw, encoded)
	}
}
