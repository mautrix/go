//go:build !goolm

package olm

// #cgo LDFLAGS: -lolm -lstdc++
// #include <olm/olm.h>
import "C"

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"unsafe"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	"github.com/element-hq/mautrix-go/crypto/canonicaljson"
	"github.com/element-hq/mautrix-go/id"
)

// Account stores a device account for end to end encrypted messaging.
type Account struct {
	int *C.OlmAccount
	mem []byte
}

// AccountFromPickled loads an Account from a pickled base64 string.  Decrypts
// the Account using the supplied key.  Returns error on failure.  If the key
// doesn't match the one used to encrypt the Account then the error will be
// "BAD_ACCOUNT_KEY".  If the base64 couldn't be decoded then the error will be
// "INVALID_BASE64".
func AccountFromPickled(pickled, key []byte) (*Account, error) {
	if len(pickled) == 0 {
		return nil, EmptyInput
	}
	a := NewBlankAccount()
	return a, a.Unpickle(pickled, key)
}

func NewBlankAccount() *Account {
	memory := make([]byte, accountSize())
	return &Account{
		int: C.olm_account(unsafe.Pointer(&memory[0])),
		mem: memory,
	}
}

// NewAccount creates a new Account.
func NewAccount() *Account {
	a := NewBlankAccount()
	random := make([]byte, a.createRandomLen()+1)
	_, err := rand.Read(random)
	if err != nil {
		panic(NotEnoughGoRandom)
	}
	r := C.olm_create_account(
		(*C.OlmAccount)(a.int),
		unsafe.Pointer(&random[0]),
		C.size_t(len(random)))
	if r == errorVal() {
		panic(a.lastError())
	} else {
		return a
	}
}

// accountSize returns the size of an account object in bytes.
func accountSize() uint {
	return uint(C.olm_account_size())
}

// lastError returns an error describing the most recent error to happen to an
// account.
func (a *Account) lastError() error {
	return convertError(C.GoString(C.olm_account_last_error((*C.OlmAccount)(a.int))))
}

// Clear clears the memory used to back this Account.
func (a *Account) Clear() error {
	r := C.olm_clear_account((*C.OlmAccount)(a.int))
	if r == errorVal() {
		return a.lastError()
	} else {
		return nil
	}
}

// pickleLen returns the number of bytes needed to store an Account.
func (a *Account) pickleLen() uint {
	return uint(C.olm_pickle_account_length((*C.OlmAccount)(a.int)))
}

// createRandomLen returns the number of random bytes needed to create an
// Account.
func (a *Account) createRandomLen() uint {
	return uint(C.olm_create_account_random_length((*C.OlmAccount)(a.int)))
}

// identityKeysLen returns the size of the output buffer needed to hold the
// identity keys.
func (a *Account) identityKeysLen() uint {
	return uint(C.olm_account_identity_keys_length((*C.OlmAccount)(a.int)))
}

// signatureLen returns the length of an ed25519 signature encoded as base64.
func (a *Account) signatureLen() uint {
	return uint(C.olm_account_signature_length((*C.OlmAccount)(a.int)))
}

// oneTimeKeysLen returns the size of the output buffer needed to hold the one
// time keys.
func (a *Account) oneTimeKeysLen() uint {
	return uint(C.olm_account_one_time_keys_length((*C.OlmAccount)(a.int)))
}

// genOneTimeKeysRandomLen returns the number of random bytes needed to
// generate a given number of new one time keys.
func (a *Account) genOneTimeKeysRandomLen(num uint) uint {
	return uint(C.olm_account_generate_one_time_keys_random_length(
		(*C.OlmAccount)(a.int),
		C.size_t(num)))
}

// Pickle returns an Account as a base64 string. Encrypts the Account using the
// supplied key.
func (a *Account) Pickle(key []byte) []byte {
	if len(key) == 0 {
		panic(NoKeyProvided)
	}
	pickled := make([]byte, a.pickleLen())
	r := C.olm_pickle_account(
		(*C.OlmAccount)(a.int),
		unsafe.Pointer(&key[0]),
		C.size_t(len(key)),
		unsafe.Pointer(&pickled[0]),
		C.size_t(len(pickled)))
	if r == errorVal() {
		panic(a.lastError())
	}
	return pickled[:r]
}

func (a *Account) Unpickle(pickled, key []byte) error {
	if len(key) == 0 {
		return NoKeyProvided
	}
	r := C.olm_unpickle_account(
		(*C.OlmAccount)(a.int),
		unsafe.Pointer(&key[0]),
		C.size_t(len(key)),
		unsafe.Pointer(&pickled[0]),
		C.size_t(len(pickled)))
	if r == errorVal() {
		return a.lastError()
	}
	return nil
}

// Deprecated
func (a *Account) GobEncode() ([]byte, error) {
	pickled := a.Pickle(pickleKey)
	length := base64.RawStdEncoding.DecodedLen(len(pickled))
	rawPickled := make([]byte, length)
	_, err := base64.RawStdEncoding.Decode(rawPickled, pickled)
	return rawPickled, err
}

// Deprecated
func (a *Account) GobDecode(rawPickled []byte) error {
	if a.int == nil {
		*a = *NewBlankAccount()
	}
	length := base64.RawStdEncoding.EncodedLen(len(rawPickled))
	pickled := make([]byte, length)
	base64.RawStdEncoding.Encode(pickled, rawPickled)
	return a.Unpickle(pickled, pickleKey)
}

// Deprecated
func (a *Account) MarshalJSON() ([]byte, error) {
	pickled := a.Pickle(pickleKey)
	quotes := make([]byte, len(pickled)+2)
	quotes[0] = '"'
	quotes[len(quotes)-1] = '"'
	copy(quotes[1:len(quotes)-1], pickled)
	return quotes, nil
}

// Deprecated
func (a *Account) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || data[0] != '"' || data[len(data)-1] != '"' {
		return InputNotJSONString
	}
	if a.int == nil {
		*a = *NewBlankAccount()
	}
	return a.Unpickle(data[1:len(data)-1], pickleKey)
}

// IdentityKeysJSON returns the public parts of the identity keys for the Account.
func (a *Account) IdentityKeysJSON() []byte {
	identityKeys := make([]byte, a.identityKeysLen())
	r := C.olm_account_identity_keys(
		(*C.OlmAccount)(a.int),
		unsafe.Pointer(&identityKeys[0]),
		C.size_t(len(identityKeys)))
	if r == errorVal() {
		panic(a.lastError())
	} else {
		return identityKeys
	}
}

// IdentityKeys returns the public parts of the Ed25519 and Curve25519 identity
// keys for the Account.
func (a *Account) IdentityKeys() (id.Ed25519, id.Curve25519) {
	identityKeysJSON := a.IdentityKeysJSON()
	results := gjson.GetManyBytes(identityKeysJSON, "ed25519", "curve25519")
	return id.Ed25519(results[0].Str), id.Curve25519(results[1].Str)
}

// Sign returns the signature of a message using the ed25519 key for this
// Account.
func (a *Account) Sign(message []byte) []byte {
	if len(message) == 0 {
		panic(EmptyInput)
	}
	signature := make([]byte, a.signatureLen())
	r := C.olm_account_sign(
		(*C.OlmAccount)(a.int),
		unsafe.Pointer(&message[0]),
		C.size_t(len(message)),
		unsafe.Pointer(&signature[0]),
		C.size_t(len(signature)))
	if r == errorVal() {
		panic(a.lastError())
	}
	return signature
}

// SignJSON signs the given JSON object following the Matrix specification:
// https://matrix.org/docs/spec/appendices#signing-json
func (a *Account) SignJSON(obj interface{}) (string, error) {
	objJSON, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	objJSON, _ = sjson.DeleteBytes(objJSON, "unsigned")
	objJSON, _ = sjson.DeleteBytes(objJSON, "signatures")
	return string(a.Sign(canonicaljson.CanonicalJSONAssumeValid(objJSON))), nil
}

// OneTimeKeys returns the public parts of the unpublished one time keys for
// the Account.
//
// The returned data is a struct with the single value "Curve25519", which is
// itself an object mapping key id to base64-encoded Curve25519 key.  For
// example:
//
//	{
//	    Curve25519: {
//	        "AAAAAA": "wo76WcYtb0Vk/pBOdmduiGJ0wIEjW4IBMbbQn7aSnTo",
//	        "AAAAAB": "LRvjo46L1X2vx69sS9QNFD29HWulxrmW11Up5AfAjgU"
//	    }
//	}
func (a *Account) OneTimeKeys() map[string]id.Curve25519 {
	oneTimeKeysJSON := make([]byte, a.oneTimeKeysLen())
	r := C.olm_account_one_time_keys(
		(*C.OlmAccount)(a.int),
		unsafe.Pointer(&oneTimeKeysJSON[0]),
		C.size_t(len(oneTimeKeysJSON)))
	if r == errorVal() {
		panic(a.lastError())
	}
	var oneTimeKeys struct {
		Curve25519 map[string]id.Curve25519 `json:"curve25519"`
	}
	err := json.Unmarshal(oneTimeKeysJSON, &oneTimeKeys)
	if err != nil {
		panic(err)
	}
	return oneTimeKeys.Curve25519
}

// MarkKeysAsPublished marks the current set of one time keys as being
// published.
func (a *Account) MarkKeysAsPublished() {
	C.olm_account_mark_keys_as_published((*C.OlmAccount)(a.int))
}

// MaxNumberOfOneTimeKeys returns the largest number of one time keys this
// Account can store.
func (a *Account) MaxNumberOfOneTimeKeys() uint {
	return uint(C.olm_account_max_number_of_one_time_keys((*C.OlmAccount)(a.int)))
}

// GenOneTimeKeys generates a number of new one time keys.  If the total number
// of keys stored by this Account exceeds MaxNumberOfOneTimeKeys then the old
// keys are discarded.
func (a *Account) GenOneTimeKeys(num uint) {
	random := make([]byte, a.genOneTimeKeysRandomLen(num)+1)
	_, err := rand.Read(random)
	if err != nil {
		panic(NotEnoughGoRandom)
	}
	r := C.olm_account_generate_one_time_keys(
		(*C.OlmAccount)(a.int),
		C.size_t(num),
		unsafe.Pointer(&random[0]),
		C.size_t(len(random)))
	if r == errorVal() {
		panic(a.lastError())
	}
}

// NewOutboundSession creates a new out-bound session for sending messages to a
// given curve25519 identityKey and oneTimeKey.  Returns error on failure.  If the
// keys couldn't be decoded as base64 then the error will be "INVALID_BASE64"
func (a *Account) NewOutboundSession(theirIdentityKey, theirOneTimeKey id.Curve25519) (*Session, error) {
	if len(theirIdentityKey) == 0 || len(theirOneTimeKey) == 0 {
		return nil, EmptyInput
	}
	s := NewBlankSession()
	random := make([]byte, s.createOutboundRandomLen()+1)
	_, err := rand.Read(random)
	if err != nil {
		panic(NotEnoughGoRandom)
	}
	r := C.olm_create_outbound_session(
		(*C.OlmSession)(s.int),
		(*C.OlmAccount)(a.int),
		unsafe.Pointer(&([]byte(theirIdentityKey)[0])),
		C.size_t(len(theirIdentityKey)),
		unsafe.Pointer(&([]byte(theirOneTimeKey)[0])),
		C.size_t(len(theirOneTimeKey)),
		unsafe.Pointer(&random[0]),
		C.size_t(len(random)))
	if r == errorVal() {
		return nil, s.lastError()
	}
	return s, nil
}

// NewInboundSession creates a new in-bound session for sending/receiving
// messages from an incoming PRE_KEY message.  Returns error on failure.  If
// the base64 couldn't be decoded then the error will be "INVALID_BASE64".  If
// the message was for an unsupported protocol version then the error will be
// "BAD_MESSAGE_VERSION".  If the message couldn't be decoded then then the
// error will be "BAD_MESSAGE_FORMAT".  If the message refers to an unknown one
// time key then the error will be "BAD_MESSAGE_KEY_ID".
func (a *Account) NewInboundSession(oneTimeKeyMsg string) (*Session, error) {
	if len(oneTimeKeyMsg) == 0 {
		return nil, EmptyInput
	}
	s := NewBlankSession()
	r := C.olm_create_inbound_session(
		(*C.OlmSession)(s.int),
		(*C.OlmAccount)(a.int),
		unsafe.Pointer(&([]byte(oneTimeKeyMsg)[0])),
		C.size_t(len(oneTimeKeyMsg)))
	if r == errorVal() {
		return nil, s.lastError()
	}
	return s, nil
}

// NewInboundSessionFrom creates a new in-bound session for sending/receiving
// messages from an incoming PRE_KEY message.  Returns error on failure.  If
// the base64 couldn't be decoded then the error will be "INVALID_BASE64".  If
// the message was for an unsupported protocol version then the error will be
// "BAD_MESSAGE_VERSION".  If the message couldn't be decoded then then the
// error will be "BAD_MESSAGE_FORMAT".  If the message refers to an unknown one
// time key then the error will be "BAD_MESSAGE_KEY_ID".
func (a *Account) NewInboundSessionFrom(theirIdentityKey id.Curve25519, oneTimeKeyMsg string) (*Session, error) {
	if len(theirIdentityKey) == 0 || len(oneTimeKeyMsg) == 0 {
		return nil, EmptyInput
	}
	s := NewBlankSession()
	r := C.olm_create_inbound_session_from(
		(*C.OlmSession)(s.int),
		(*C.OlmAccount)(a.int),
		unsafe.Pointer(&([]byte(theirIdentityKey)[0])),
		C.size_t(len(theirIdentityKey)),
		unsafe.Pointer(&([]byte(oneTimeKeyMsg)[0])),
		C.size_t(len(oneTimeKeyMsg)))
	if r == errorVal() {
		return nil, s.lastError()
	}
	return s, nil
}

// RemoveOneTimeKeys removes the one time keys that the session used from the
// Account.  Returns error on failure.  If the Account doesn't have any
// matching one time keys then the error will be "BAD_MESSAGE_KEY_ID".
func (a *Account) RemoveOneTimeKeys(s *Session) error {
	r := C.olm_remove_one_time_keys(
		(*C.OlmAccount)(a.int),
		(*C.OlmSession)(s.int))
	if r == errorVal() {
		return a.lastError()
	}
	return nil
}
