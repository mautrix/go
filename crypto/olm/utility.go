//go:build !goolm

package olm

// #cgo LDFLAGS: -lolm -lstdc++
// #include <olm/olm.h>
import "C"

import (
	"encoding/json"
	"fmt"
	"unsafe"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"go.mau.fi/util/exgjson"

	"github.com/element-hq/mautrix-go/crypto/canonicaljson"
	"github.com/element-hq/mautrix-go/id"
)

// Utility stores the necessary state to perform hash and signature
// verification operations.
type Utility struct {
	int *C.OlmUtility
	mem []byte
}

// utilitySize returns the size of a utility object in bytes.
func utilitySize() uint {
	return uint(C.olm_utility_size())
}

// sha256Len returns the length of the buffer needed to hold the SHA-256 hash.
func (u *Utility) sha256Len() uint {
	return uint(C.olm_sha256_length((*C.OlmUtility)(u.int)))
}

// lastError returns an error describing the most recent error to happen to a
// utility.
func (u *Utility) lastError() error {
	return convertError(C.GoString(C.olm_utility_last_error((*C.OlmUtility)(u.int))))
}

// Clear clears the memory used to back this utility.
func (u *Utility) Clear() error {
	r := C.olm_clear_utility((*C.OlmUtility)(u.int))
	if r == errorVal() {
		return u.lastError()
	}
	return nil
}

// NewUtility creates a new utility.
func NewUtility() *Utility {
	memory := make([]byte, utilitySize())
	return &Utility{
		int: C.olm_utility(unsafe.Pointer(&memory[0])),
		mem: memory,
	}
}

// Sha256 calculates the SHA-256 hash of the input and encodes it as base64.
func (u *Utility) Sha256(input string) string {
	if len(input) == 0 {
		panic(EmptyInput)
	}
	output := make([]byte, u.sha256Len())
	r := C.olm_sha256(
		(*C.OlmUtility)(u.int),
		unsafe.Pointer(&([]byte(input)[0])),
		C.size_t(len(input)),
		unsafe.Pointer(&(output[0])),
		C.size_t(len(output)))
	if r == errorVal() {
		panic(u.lastError())
	}
	return string(output)
}

// VerifySignature verifies an ed25519 signature.  Returns true if the verification
// suceeds or false otherwise.  Returns error on failure.  If the key was too
// small then the error will be "INVALID_BASE64".
func (u *Utility) VerifySignature(message string, key id.Ed25519, signature string) (ok bool, err error) {
	if len(message) == 0 || len(key) == 0 || len(signature) == 0 {
		return false, EmptyInput
	}
	r := C.olm_ed25519_verify(
		(*C.OlmUtility)(u.int),
		unsafe.Pointer(&([]byte(key)[0])),
		C.size_t(len(key)),
		unsafe.Pointer(&([]byte(message)[0])),
		C.size_t(len(message)),
		unsafe.Pointer(&([]byte(signature)[0])),
		C.size_t(len(signature)))
	if r == errorVal() {
		err = u.lastError()
		if err == BadMessageMAC {
			err = nil
		}
	} else {
		ok = true
	}
	return ok, err
}

// VerifySignatureJSON verifies the signature in the JSON object _obj following
// the Matrix specification:
// https://matrix.org/speculator/spec/drafts%2Fe2e/appendices.html#signing-json
// If the _obj is a struct, the `json` tags will be honored.
func (u *Utility) VerifySignatureJSON(obj interface{}, userID id.UserID, keyName string, key id.Ed25519) (bool, error) {
	var err error
	objJSON, ok := obj.(json.RawMessage)
	if !ok {
		objJSON, err = json.Marshal(obj)
		if err != nil {
			return false, err
		}
	}
	sig := gjson.GetBytes(objJSON, exgjson.Path("signatures", string(userID), fmt.Sprintf("ed25519:%s", keyName)))
	if !sig.Exists() || sig.Type != gjson.String {
		return false, SignatureNotFound
	}
	objJSON, err = sjson.DeleteBytes(objJSON, "unsigned")
	if err != nil {
		return false, err
	}
	objJSON, err = sjson.DeleteBytes(objJSON, "signatures")
	if err != nil {
		return false, err
	}
	objJSONString := string(canonicaljson.CanonicalJSONAssumeValid(objJSON))
	return u.VerifySignature(objJSONString, key, sig.Str)
}

// VerifySignatureJSON verifies the signature in the JSON object _obj following
// the Matrix specification:
// https://matrix.org/speculator/spec/drafts%2Fe2e/appendices.html#signing-json
// This function is a wrapper over Utility.VerifySignatureJSON that creates and
// destroys the Utility object transparently.
// If the _obj is a struct, the `json` tags will be honored.
func VerifySignatureJSON(obj interface{}, userID id.UserID, keyName string, key id.Ed25519) (bool, error) {
	u := NewUtility()
	defer u.Clear()
	return u.VerifySignatureJSON(obj, userID, keyName, key)
}
