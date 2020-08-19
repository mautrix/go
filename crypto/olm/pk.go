package olm

// #cgo LDFLAGS: -lolm -lstdc++
// #include <olm/olm.h>
// #include <olm/pk.h>
import "C"

import (
	"crypto/rand"
	"unsafe"
)

// PkSigning stores a key pair for signing messages.
type PkSigning struct {
	int       *C.OlmPkSigning
	PublicKey []byte
}

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

func newBlackPkSigning() *PkSigning {
	memory := make([]byte, pkSigningSize())
	return &PkSigning{
		int: C.olm_pk_signing(unsafe.Pointer(&memory[0])),
	}
}

// Clear clears the underlying memory of a PkSigning object.
func (p *PkSigning) Clear() {
	C.olm_clear_pk_signing((*C.OlmPkSigning)(p.int))
}

// NewPkSigning creates a new PkSigning object, containing a key pair for signing messages.
func NewPkSigning() (*PkSigning, error) {
	p := newBlackPkSigning()
	p.Clear()
	pubKey := make([]byte, pkSigningPublicKeyLength())
	// Make the slice be at least length 1
	random := make([]byte, pkSigningSeedLength())
	_, err := rand.Read(random)
	if err != nil {
		panic(NotEnoughGoRandom)
	}
	if C.olm_pk_signing_key_from_seed((*C.OlmPkSigning)(p.int),
		unsafe.Pointer(&pubKey[0]), C.size_t(len(pubKey)),
		unsafe.Pointer(&random[0]), C.size_t(len(random))) == errorVal() {
		return nil, p.lastError()
	}
	p.PublicKey = pubKey
	return p, nil
}

// Sign creates a signature for the given message using this key.
func (p *PkSigning) Sign(message []byte) ([]byte, error) {
	signature := make([]byte, pkSigningSignatureLength())
	if C.olm_pk_sign((*C.OlmPkSigning)(p.int), (*C.uint8_t)(unsafe.Pointer(&message[0])), C.size_t(len(message)),
		(*C.uint8_t)(unsafe.Pointer(&signature[0])), C.size_t(len(signature))) == errorVal() {
		return nil, p.lastError()
	}
	return signature, nil
}

// lastError returns the last error that happened in relation to this PkSigning object.
func (p *PkSigning) lastError() error {
	return convertError(C.GoString(C.olm_pk_signing_last_error((*C.OlmPkSigning)(p.int))))
}
