package ratchet_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"maunium.net/go/mautrix/crypto/goolm/cipher"
	"maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/crypto/goolm/ratchet"
)

var (
	sharedSecret = []byte("A secret")
)

func initializeRatchets() (*ratchet.Ratchet, *ratchet.Ratchet, error) {
	ratchet.KdfInfo = struct {
		Root    []byte
		Ratchet []byte
	}{
		Root:    []byte("Olm"),
		Ratchet: []byte("OlmRatchet"),
	}
	ratchet.RatchetCipher = cipher.NewAESSHA256([]byte("OlmMessageKeys"))
	aliceRatchet := ratchet.New()
	bobRatchet := ratchet.New()

	aliceKey, err := crypto.Curve25519GenerateKey()
	if err != nil {
		return nil, nil, err
	}

	aliceRatchet.InitializeAsAlice(sharedSecret, aliceKey)
	bobRatchet.InitializeAsBob(sharedSecret, aliceKey.PublicKey)
	return aliceRatchet, bobRatchet, nil
}

func TestSendReceive(t *testing.T) {
	aliceRatchet, bobRatchet, err := initializeRatchets()
	if err != nil {
		t.Fatal(err)
	}

	plainText := []byte("Hello Bob")

	//Alice sends Bob a message
	encryptedMessage, err := aliceRatchet.Encrypt(plainText)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := bobRatchet.Decrypt(encryptedMessage)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plainText, decrypted) {
		t.Fatalf("expected '%v' from decryption but got '%v'", plainText, decrypted)
	}

	//Bob sends Alice a message
	plainText = []byte("Hello Alice")
	encryptedMessage, err = bobRatchet.Encrypt(plainText)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err = aliceRatchet.Decrypt(encryptedMessage)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plainText, decrypted) {
		t.Fatalf("expected '%v' from decryption but got '%v'", plainText, decrypted)
	}
}

func TestOutOfOrder(t *testing.T) {
	aliceRatchet, bobRatchet, err := initializeRatchets()
	if err != nil {
		t.Fatal(err)
	}

	plainText1 := []byte("First Message")
	plainText2 := []byte("Second Messsage. A bit longer than the first.")

	/* Alice sends Bob two messages and they arrive out of order */
	message1Encrypted, err := aliceRatchet.Encrypt(plainText1)
	if err != nil {
		t.Fatal(err)
	}
	message2Encrypted, err := aliceRatchet.Encrypt(plainText2)
	if err != nil {
		t.Fatal(err)
	}

	decrypted2, err := bobRatchet.Decrypt(message2Encrypted)
	if err != nil {
		t.Fatal(err)
	}
	decrypted1, err := bobRatchet.Decrypt(message1Encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plainText1, decrypted1) {
		t.Fatalf("expected '%v' from decryption but got '%v'", plainText1, decrypted1)
	}
	if !bytes.Equal(plainText2, decrypted2) {
		t.Fatalf("expected '%v' from decryption but got '%v'", plainText2, decrypted2)
	}
}

func TestMoreMessages(t *testing.T) {
	aliceRatchet, bobRatchet, err := initializeRatchets()
	if err != nil {
		t.Fatal(err)
	}
	plainText := []byte("These 15 bytes")
	for i := 0; i < 8; i++ {
		messageEncrypted, err := aliceRatchet.Encrypt(plainText)
		if err != nil {
			t.Fatal(err)
		}
		decrypted, err := bobRatchet.Decrypt(messageEncrypted)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(plainText, decrypted) {
			t.Fatalf("expected '%v' from decryption but got '%v'", plainText, decrypted)
		}
	}
	for i := 0; i < 8; i++ {
		messageEncrypted, err := bobRatchet.Encrypt(plainText)
		if err != nil {
			t.Fatal(err)
		}
		decrypted, err := aliceRatchet.Decrypt(messageEncrypted)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(plainText, decrypted) {
			t.Fatalf("expected '%v' from decryption but got '%v'", plainText, decrypted)
		}
	}
	messageEncrypted, err := aliceRatchet.Encrypt(plainText)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := bobRatchet.Decrypt(messageEncrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plainText, decrypted) {
		t.Fatalf("expected '%v' from decryption but got '%v'", plainText, decrypted)
	}
}

func TestJSONEncoding(t *testing.T) {
	aliceRatchet, bobRatchet, err := initializeRatchets()
	if err != nil {
		t.Fatal(err)
	}
	marshaled, err := json.Marshal(aliceRatchet)
	if err != nil {
		t.Fatal(err)
	}

	newRatcher := ratchet.Ratchet{}
	err = json.Unmarshal(marshaled, &newRatcher)
	if err != nil {
		t.Fatal(err)
	}

	plainText := []byte("These 15 bytes")

	messageEncrypted, err := newRatcher.Encrypt(plainText)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := bobRatchet.Decrypt(messageEncrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plainText, decrypted) {
		t.Fatalf("expected '%v' from decryption but got '%v'", plainText, decrypted)
	}

}
