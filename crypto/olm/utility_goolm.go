//go:build goolm

package olm

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"go.mau.fi/util/exgjson"

	"github.com/element-hq/mautrix-go/crypto/canonicaljson"
	"github.com/element-hq/mautrix-go/crypto/goolm/utilities"
	"github.com/element-hq/mautrix-go/id"
)

// Utility stores the necessary state to perform hash and signature
// verification operations.
type Utility struct{}

// Clear clears the memory used to back this utility.
func (u *Utility) Clear() error {
	return nil
}

// NewUtility creates a new utility.
func NewUtility() *Utility {
	return &Utility{}
}

// Sha256 calculates the SHA-256 hash of the input and encodes it as base64.
func (u *Utility) Sha256(input string) string {
	if len(input) == 0 {
		panic(EmptyInput)
	}
	hash := sha256.Sum256([]byte(input))
	return base64.RawStdEncoding.EncodeToString(hash[:])
}

// VerifySignature verifies an ed25519 signature.  Returns true if the verification
// suceeds or false otherwise.  Returns error on failure.  If the key was too
// small then the error will be "INVALID_BASE64".
func (u *Utility) VerifySignature(message string, key id.Ed25519, signature string) (ok bool, err error) {
	if len(message) == 0 || len(key) == 0 || len(signature) == 0 {
		return false, EmptyInput
	}
	return utilities.VerifySignature([]byte(message), key, []byte(signature))
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
