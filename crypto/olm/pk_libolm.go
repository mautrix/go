// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build !goolm

package olm

// #cgo LDFLAGS: -lolm -lstdc++
// #include <olm/olm.h>
// #include <olm/pk.h>
import "C"

import (
	"crypto/rand"
	"encoding/json"
	"unsafe"

	"github.com/tidwall/sjson"

	"maunium.net/go/mautrix/crypto/canonicaljson"
	"maunium.net/go/mautrix/id"
)

// LibOlmPKSigning stores a key pair for signing messages.
type LibOlmPKSigning struct {
	int       *C.OlmPkSigning
	mem       []byte
	publicKey id.Ed25519
	seed      []byte
}

// Ensure that LibOlmPKSigning implements PKSigning.
var _ PKSigning = (*LibOlmPKSigning)(nil)

func pkSigningSize() uint {
	return uint(C.olm_pk_signing_size())
}

func pkSigningSeedLength() uint {
	return uint(C.olm_pk_signing_seed_length())
}

func pkSigningPublicKeyLength() uint {
	return uint(C.olm_pk_signing_public_key_length())
}

func pkSigningSignatureLength() uint {
	return uint(C.olm_pk_signature_length())
}

func newBlankPKSigning() *LibOlmPKSigning {
	memory := make([]byte, pkSigningSize())
	return &LibOlmPKSigning{
		int: C.olm_pk_signing(unsafe.Pointer(&memory[0])),
		mem: memory,
	}
}

// NewPKSigningFromSeed creates a new [PKSigning] object using the given seed.
func NewPKSigningFromSeed(seed []byte) (PKSigning, error) {
	p := newBlankPKSigning()
	p.clear()
	pubKey := make([]byte, pkSigningPublicKeyLength())
	if C.olm_pk_signing_key_from_seed((*C.OlmPkSigning)(p.int),
		unsafe.Pointer(&pubKey[0]), C.size_t(len(pubKey)),
		unsafe.Pointer(&seed[0]), C.size_t(len(seed))) == errorVal() {
		return nil, p.lastError()
	}
	p.publicKey = id.Ed25519(pubKey)
	p.seed = seed
	return p, nil
}

// NewPKSigning creates a new LibOlmPKSigning object, containing a key pair for
// signing messages.
func NewPKSigning() (PKSigning, error) {
	// Generate the seed
	seed := make([]byte, pkSigningSeedLength())
	_, err := rand.Read(seed)
	if err != nil {
		panic(NotEnoughGoRandom)
	}
	pk, err := NewPKSigningFromSeed(seed)
	return pk, err
}

func (p *LibOlmPKSigning) PublicKey() id.Ed25519 {
	return p.publicKey
}

func (p *LibOlmPKSigning) Seed() []byte {
	return p.seed
}

// clear clears the underlying memory of a LibOlmPKSigning object.
func (p *LibOlmPKSigning) clear() {
	C.olm_clear_pk_signing((*C.OlmPkSigning)(p.int))
}

// Sign creates a signature for the given message using this key.
func (p *LibOlmPKSigning) Sign(message []byte) ([]byte, error) {
	signature := make([]byte, pkSigningSignatureLength())
	if C.olm_pk_sign((*C.OlmPkSigning)(p.int), (*C.uint8_t)(unsafe.Pointer(&message[0])), C.size_t(len(message)),
		(*C.uint8_t)(unsafe.Pointer(&signature[0])), C.size_t(len(signature))) == errorVal() {
		return nil, p.lastError()
	}
	return signature, nil
}

// SignJSON creates a signature for the given object after encoding it to canonical JSON.
func (p *LibOlmPKSigning) SignJSON(obj interface{}) (string, error) {
	objJSON, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	objJSON, _ = sjson.DeleteBytes(objJSON, "unsigned")
	objJSON, _ = sjson.DeleteBytes(objJSON, "signatures")
	signature, err := p.Sign(canonicaljson.CanonicalJSONAssumeValid(objJSON))
	if err != nil {
		return "", err
	}
	return string(signature), nil
}

// lastError returns the last error that happened in relation to this
// LibOlmPKSigning object.
func (p *LibOlmPKSigning) lastError() error {
	return convertError(C.GoString(C.olm_pk_signing_last_error((*C.OlmPkSigning)(p.int))))
}

type LibOlmPKDecryption struct {
	int       *C.OlmPkDecryption
	mem       []byte
	PublicKey []byte
}

func pkDecryptionSize() uint {
	return uint(C.olm_pk_decryption_size())
}

func pkDecryptionPublicKeySize() uint {
	return uint(C.olm_pk_key_length())
}

func NewPkDecryption(privateKey []byte) (*LibOlmPKDecryption, error) {
	memory := make([]byte, pkDecryptionSize())
	p := &LibOlmPKDecryption{
		int: C.olm_pk_decryption(unsafe.Pointer(&memory[0])),
		mem: memory,
	}
	p.clear()
	pubKey := make([]byte, pkDecryptionPublicKeySize())

	if C.olm_pk_key_from_private((*C.OlmPkDecryption)(p.int),
		unsafe.Pointer(&pubKey[0]), C.size_t(len(pubKey)),
		unsafe.Pointer(&privateKey[0]), C.size_t(len(privateKey))) == errorVal() {
		return nil, p.lastError()
	}
	p.PublicKey = pubKey

	return p, nil
}

func (p *LibOlmPKDecryption) Decrypt(ephemeralKey []byte, mac []byte, ciphertext []byte) ([]byte, error) {
	maxPlaintextLength := uint(C.olm_pk_max_plaintext_length((*C.OlmPkDecryption)(p.int), C.size_t(len(ciphertext))))
	plaintext := make([]byte, maxPlaintextLength)

	size := C.olm_pk_decrypt((*C.OlmPkDecryption)(p.int),
		unsafe.Pointer(&ephemeralKey[0]), C.size_t(len(ephemeralKey)),
		unsafe.Pointer(&mac[0]), C.size_t(len(mac)),
		unsafe.Pointer(&ciphertext[0]), C.size_t(len(ciphertext)),
		unsafe.Pointer(&plaintext[0]), C.size_t(len(plaintext)))
	if size == errorVal() {
		return nil, p.lastError()
	}

	return plaintext[:size], nil
}

// Clear clears the underlying memory of a PkDecryption object.
func (p *LibOlmPKDecryption) clear() {
	C.olm_clear_pk_decryption((*C.OlmPkDecryption)(p.int))
}

// lastError returns the last error that happened in relation to this
// LibOlmPKDecryption object.
func (p *LibOlmPKDecryption) lastError() error {
	return convertError(C.GoString(C.olm_pk_decryption_last_error((*C.OlmPkDecryption)(p.int))))
}
