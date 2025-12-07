// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package libolm

// #cgo LDFLAGS: -lolm -lstdc++
// #include <olm/olm.h>
// #include <olm/pk.h>
import "C"

import (
	"crypto/rand"
	"encoding/json"
	"runtime"
	"unsafe"

	"github.com/tidwall/sjson"

	"maunium.net/go/mautrix/crypto/canonicaljson"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/id"
)

// PKSigning stores a key pair for signing messages.
type PKSigning struct {
	int       *C.OlmPkSigning
	mem       []byte
	publicKey id.Ed25519
	seed      []byte
}

// Ensure that [PKSigning] implements [olm.PKSigning].
var _ olm.PKSigning = (*PKSigning)(nil)

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

func newBlankPKSigning() *PKSigning {
	memory := make([]byte, pkSigningSize())
	return &PKSigning{
		int: C.olm_pk_signing(unsafe.Pointer(unsafe.SliceData(memory))),
		mem: memory,
	}
}

// NewPKSigningFromSeed creates a new [PKSigning] object using the given seed.
func NewPKSigningFromSeed(seed []byte) (*PKSigning, error) {
	p := newBlankPKSigning()
	p.clear()
	pubKey := make([]byte, pkSigningPublicKeyLength())
	r := C.olm_pk_signing_key_from_seed(
		(*C.OlmPkSigning)(p.int),
		unsafe.Pointer(unsafe.SliceData(pubKey)),
		C.size_t(len(pubKey)),
		unsafe.Pointer(unsafe.SliceData(seed)),
		C.size_t(len(seed)),
	)
	if r == errorVal() {
		return nil, p.lastError()
	}
	p.publicKey = id.Ed25519(pubKey)
	p.seed = seed
	return p, nil
}

// NewPKSigning creates a new [PKSigning] object, containing a key pair for
// signing messages.
func NewPKSigning() (*PKSigning, error) {
	// Generate the seed
	seed := make([]byte, pkSigningSeedLength())
	_, err := rand.Read(seed)
	if err != nil {
		panic(olm.ErrNotEnoughGoRandom)
	}
	pk, err := NewPKSigningFromSeed(seed)
	return pk, err
}

func (p *PKSigning) PublicKey() id.Ed25519 {
	return p.publicKey
}

func (p *PKSigning) Seed() []byte {
	return p.seed
}

// clear clears the underlying memory of a [PKSigning] object.
func (p *PKSigning) clear() {
	C.olm_clear_pk_signing((*C.OlmPkSigning)(p.int))
}

// Sign creates a signature for the given message using this key.
func (p *PKSigning) Sign(message []byte) ([]byte, error) {
	signature := make([]byte, pkSigningSignatureLength())
	r := C.olm_pk_sign(
		(*C.OlmPkSigning)(p.int),
		(*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(message))),
		C.size_t(len(message)),
		(*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(signature))),
		C.size_t(len(signature)),
	)
	runtime.KeepAlive(message)
	if r == errorVal() {
		return nil, p.lastError()
	}
	return signature, nil
}

// SignJSON creates a signature for the given object after encoding it to canonical JSON.
func (p *PKSigning) SignJSON(obj interface{}) (string, error) {
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
// [PKSigning] object.
func (p *PKSigning) lastError() error {
	return convertError(C.GoString(C.olm_pk_signing_last_error((*C.OlmPkSigning)(p.int))))
}

type PKDecryption struct {
	int       *C.OlmPkDecryption
	mem       []byte
	publicKey []byte
}

func pkDecryptionSize() uint {
	return uint(C.olm_pk_decryption_size())
}

func pkDecryptionPublicKeySize() uint {
	return uint(C.olm_pk_key_length())
}

func NewPkDecryption(privateKey []byte) (*PKDecryption, error) {
	memory := make([]byte, pkDecryptionSize())
	p := &PKDecryption{
		int: C.olm_pk_decryption(unsafe.Pointer(unsafe.SliceData(memory))),
		mem: memory,
	}
	p.clear()
	pubKey := make([]byte, pkDecryptionPublicKeySize())

	r := C.olm_pk_key_from_private(
		(*C.OlmPkDecryption)(p.int),
		unsafe.Pointer(unsafe.SliceData(pubKey)),
		C.size_t(len(pubKey)),
		unsafe.Pointer(unsafe.SliceData(privateKey)),
		C.size_t(len(privateKey)),
	)
	runtime.KeepAlive(privateKey)
	if r == errorVal() {
		return nil, p.lastError()
	}
	p.publicKey = pubKey

	return p, nil
}

func (p *PKDecryption) PublicKey() id.Curve25519 {
	return id.Curve25519(p.publicKey)
}

func (p *PKDecryption) Decrypt(ephemeralKey []byte, mac []byte, ciphertext []byte) ([]byte, error) {
	maxPlaintextLength := uint(C.olm_pk_max_plaintext_length(
		(*C.OlmPkDecryption)(p.int),
		C.size_t(len(ciphertext)),
	))
	plaintext := make([]byte, maxPlaintextLength)

	size := C.olm_pk_decrypt(
		(*C.OlmPkDecryption)(p.int),
		unsafe.Pointer(unsafe.SliceData(ephemeralKey)),
		C.size_t(len(ephemeralKey)),
		unsafe.Pointer(unsafe.SliceData(mac)),
		C.size_t(len(mac)),
		unsafe.Pointer(unsafe.SliceData(ciphertext)),
		C.size_t(len(ciphertext)),
		unsafe.Pointer(unsafe.SliceData(plaintext)),
		C.size_t(len(plaintext)),
	)
	runtime.KeepAlive(ephemeralKey)
	runtime.KeepAlive(mac)
	runtime.KeepAlive(ciphertext)
	if size == errorVal() {
		return nil, p.lastError()
	}

	return plaintext[:size], nil
}

// Clear clears the underlying memory of a PkDecryption object.
func (p *PKDecryption) clear() {
	C.olm_clear_pk_decryption((*C.OlmPkDecryption)(p.int))
}

// lastError returns the last error that happened in relation to this
// [PKDecryption] object.
func (p *PKDecryption) lastError() error {
	return convertError(C.GoString(C.olm_pk_decryption_last_error((*C.OlmPkDecryption)(p.int))))
}
