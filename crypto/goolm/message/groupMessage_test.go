package message

import (
	"bytes"
	"testing"
)

func TestGroupMessageDecode(t *testing.T) {
	messageRaw := []byte("\x03\x08\xC8\x01\x12\x0aciphertexthmacsha2")
	signature := []byte("signature1234567891234567890123412345678912345678912345678901234")
	messageRaw = append(messageRaw, signature...)
	expectedMessageIndex := uint32(200)
	expectedCipherText := []byte("ciphertext")

	msg := GroupMessage{}
	err := msg.Decode(messageRaw)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Version != 3 {
		t.Fatalf("Expected Version to be 3 but go %d", msg.Version)
	}
	if msg.MessageIndex != expectedMessageIndex {
		t.Fatalf("Expected message index to be %d but got %d", expectedMessageIndex, msg.MessageIndex)
	}
	if !bytes.Equal(msg.Ciphertext, expectedCipherText) {
		t.Fatalf("expected '%s' but got '%s'", expectedCipherText, msg.Ciphertext)
	}
}

func TestGroupMessageEncode(t *testing.T) {
	expectedRaw := []byte("\x03\x08\xC8\x01\x12\x0aciphertexthmacsha2signature")
	hmacsha256 := []byte("hmacsha2")
	sign := []byte("signature")
	msg := GroupMessage{
		Version:      3,
		MessageIndex: 200,
		Ciphertext:   []byte("ciphertext"),
	}
	encoded, err := msg.EncodeAndMacAndSign(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, hmacsha256...)
	encoded = append(encoded, sign...)
	if !bytes.Equal(encoded, expectedRaw) {
		t.Fatalf("expected '%s' but got '%s'", expectedRaw, encoded)
	}
}
