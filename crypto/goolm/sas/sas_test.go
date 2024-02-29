package sas_test

import (
	"bytes"
	"testing"

	"github.com/element-hq/mautrix-go/crypto/goolm/crypto"
	"github.com/element-hq/mautrix-go/crypto/goolm/sas"
)

func initSAS() (*sas.SAS, *sas.SAS, error) {
	alicePrivate := crypto.Curve25519PrivateKey([]byte{
		0x77, 0x07, 0x6D, 0x0A, 0x73, 0x18, 0xA5, 0x7D,
		0x3C, 0x16, 0xC1, 0x72, 0x51, 0xB2, 0x66, 0x45,
		0xDF, 0x4C, 0x2F, 0x87, 0xEB, 0xC0, 0x99, 0x2A,
		0xB1, 0x77, 0xFB, 0xA5, 0x1D, 0xB9, 0x2C, 0x2A,
	})
	bobPrivate := crypto.Curve25519PrivateKey([]byte{
		0x5D, 0xAB, 0x08, 0x7E, 0x62, 0x4A, 0x8A, 0x4B,
		0x79, 0xE1, 0x7F, 0x8B, 0x83, 0x80, 0x0E, 0xE6,
		0x6F, 0x3B, 0xB1, 0x29, 0x26, 0x18, 0xB6, 0xFD,
		0x1C, 0x2F, 0x8B, 0x27, 0xFF, 0x88, 0xE0, 0xEB,
	})

	aliceSAS, err := sas.New()
	if err != nil {
		return nil, nil, err
	}
	aliceSAS.KeyPair.PrivateKey = alicePrivate
	aliceSAS.KeyPair.PublicKey, err = alicePrivate.PubKey()
	if err != nil {
		return nil, nil, err
	}

	bobSAS, err := sas.New()
	if err != nil {
		return nil, nil, err
	}
	bobSAS.KeyPair.PrivateKey = bobPrivate
	bobSAS.KeyPair.PublicKey, err = bobPrivate.PubKey()
	if err != nil {
		return nil, nil, err
	}
	return aliceSAS, bobSAS, nil
}

func TestGenerateBytes(t *testing.T) {
	aliceSAS, bobSAS, err := initSAS()
	if err != nil {
		t.Fatal(err)
	}
	alicePublicEncoded := []byte("hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo")
	bobPublicEncoded := []byte("3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08")

	if !bytes.Equal(aliceSAS.GetPubkey(), alicePublicEncoded) {
		t.Fatal("public keys not equal")
	}
	if !bytes.Equal(bobSAS.GetPubkey(), bobPublicEncoded) {
		t.Fatal("public keys not equal")
	}

	err = aliceSAS.SetTheirKey(bobSAS.GetPubkey())
	if err != nil {
		t.Fatal(err)
	}
	err = bobSAS.SetTheirKey(aliceSAS.GetPubkey())
	if err != nil {
		t.Fatal(err)
	}

	aliceBytes, err := aliceSAS.GenerateBytes([]byte("SAS"), 6)
	if err != nil {
		t.Fatal(err)
	}
	bobBytes, err := bobSAS.GenerateBytes([]byte("SAS"), 6)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aliceBytes, bobBytes) {
		t.Fatal("results are not equal")
	}
}

func TestSASMac(t *testing.T) {
	aliceSAS, bobSAS, err := initSAS()
	if err != nil {
		t.Fatal(err)
	}
	err = aliceSAS.SetTheirKey(bobSAS.GetPubkey())
	if err != nil {
		t.Fatal(err)
	}
	err = bobSAS.SetTheirKey(aliceSAS.GetPubkey())
	if err != nil {
		t.Fatal(err)
	}

	plainText := []byte("Hello world!")
	info := []byte("MAC")

	aliceMac, err := aliceSAS.CalculateMAC(plainText, info)
	if err != nil {
		t.Fatal(err)
	}
	bobMac, err := bobSAS.CalculateMAC(plainText, info)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aliceMac, bobMac) {
		t.Fatal("results are not equal")
	}
}
