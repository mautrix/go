package crypto_test

import (
	"bytes"
	"testing"

	"github.com/element-hq/mautrix-go/crypto/goolm/crypto"
)

func TestEd25519(t *testing.T) {
	keypair, err := crypto.Ed25519GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("test message")
	signature := keypair.Sign(message)
	if !keypair.Verify(message, signature) {
		t.Fail()
	}
}

func TestEd25519Case1(t *testing.T) {
	//64 bytes for ed25519 package
	keyPair, err := crypto.Ed25519GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("Hello, World")

	keyPair2 := crypto.Ed25519GenerateFromPrivate(keyPair.PrivateKey)
	if !bytes.Equal(keyPair.PublicKey, keyPair2.PublicKey) {
		t.Fatal("not equal key pairs")
	}
	signature := keyPair.Sign(message)
	verified := keyPair.Verify(message, signature)
	if !verified {
		t.Fatal("message did not verify although it should")
	}
	//Now change the message and verify again
	message = append(message, []byte("a")...)
	verified = keyPair.Verify(message, signature)
	if verified {
		t.Fatal("message did verify although it should not")
	}
}

func TestEd25519Pickle(t *testing.T) {
	//create keypair
	keyPair, err := crypto.Ed25519GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	target := make([]byte, keyPair.PickleLen())
	writtenBytes, err := keyPair.PickleLibOlm(target)
	if err != nil {
		t.Fatal(err)
	}
	if writtenBytes != len(target) {
		t.Fatal("written bytes not correct")
	}

	unpickledKeyPair := crypto.Ed25519KeyPair{}
	readBytes, err := unpickledKeyPair.UnpickleLibOlm(target)
	if err != nil {
		t.Fatal(err)
	}
	if readBytes != len(target) {
		t.Fatal("read bytes not correct")
	}
	if !bytes.Equal(keyPair.PrivateKey, unpickledKeyPair.PrivateKey) {
		t.Fatal("private keys not correct")
	}
	if !bytes.Equal(keyPair.PublicKey, unpickledKeyPair.PublicKey) {
		t.Fatal("public keys not correct")
	}
}

func TestEd25519PicklePubKeyOnly(t *testing.T) {
	//create keypair
	keyPair, err := crypto.Ed25519GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	//Remove privateKey
	keyPair.PrivateKey = nil
	target := make([]byte, keyPair.PickleLen())
	writtenBytes, err := keyPair.PickleLibOlm(target)
	if err != nil {
		t.Fatal(err)
	}
	if writtenBytes != len(target) {
		t.Fatal("written bytes not correct")
	}
	unpickledKeyPair := crypto.Ed25519KeyPair{}
	readBytes, err := unpickledKeyPair.UnpickleLibOlm(target)
	if err != nil {
		t.Fatal(err)
	}
	if readBytes != len(target) {
		t.Fatal("read bytes not correct")
	}
	if !bytes.Equal(keyPair.PrivateKey, unpickledKeyPair.PrivateKey) {
		t.Fatal("private keys not correct")
	}
	if !bytes.Equal(keyPair.PublicKey, unpickledKeyPair.PublicKey) {
		t.Fatal("public keys not correct")
	}
}

func TestEd25519PicklePrivKeyOnly(t *testing.T) {
	//create keypair
	keyPair, err := crypto.Ed25519GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	//Remove public
	keyPair.PublicKey = nil
	target := make([]byte, keyPair.PickleLen())
	writtenBytes, err := keyPair.PickleLibOlm(target)
	if err != nil {
		t.Fatal(err)
	}
	if writtenBytes != len(target) {
		t.Fatal("written bytes not correct")
	}
	unpickledKeyPair := crypto.Ed25519KeyPair{}
	readBytes, err := unpickledKeyPair.UnpickleLibOlm(target)
	if err != nil {
		t.Fatal(err)
	}
	if readBytes != len(target) {
		t.Fatal("read bytes not correct")
	}
	if !bytes.Equal(keyPair.PrivateKey, unpickledKeyPair.PrivateKey) {
		t.Fatal("private keys not correct")
	}
	if !bytes.Equal(keyPair.PublicKey, unpickledKeyPair.PublicKey) {
		t.Fatal("public keys not correct")
	}
}
