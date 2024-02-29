//go:build goolm

package olm

import (
	"encoding/json"

	"github.com/tidwall/sjson"

	"github.com/element-hq/mautrix-go/crypto/canonicaljson"
	"github.com/element-hq/mautrix-go/crypto/goolm/account"
	"github.com/element-hq/mautrix-go/id"
)

// Account stores a device account for end to end encrypted messaging.
type Account struct {
	account.Account
}

// NewAccount creates a new Account.
func NewAccount() *Account {
	a, err := account.NewAccount(nil)
	if err != nil {
		panic(err)
	}
	ac := &Account{}
	ac.Account = *a
	return ac
}

func NewBlankAccount() *Account {
	return &Account{}
}

// Clear clears the memory used to back this Account.
func (a *Account) Clear() error {
	a.Account = account.Account{}
	return nil
}

// Pickle returns an Account as a base64 string. Encrypts the Account using the
// supplied key.
func (a *Account) Pickle(key []byte) []byte {
	if len(key) == 0 {
		panic(NoKeyProvided)
	}
	pickled, err := a.Account.Pickle(key)
	if err != nil {
		panic(err)
	}
	return pickled
}

// IdentityKeysJSON returns the public parts of the identity keys for the Account.
func (a *Account) IdentityKeysJSON() []byte {
	identityKeys, err := a.Account.IdentityKeysJSON()
	if err != nil {
		panic(err)
	}
	return identityKeys
}

// Sign returns the signature of a message using the ed25519 key for this
// Account.
func (a *Account) Sign(message []byte) []byte {
	if len(message) == 0 {
		panic(EmptyInput)
	}
	signature, err := a.Account.Sign(message)
	if err != nil {
		panic(err)
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

// MaxNumberOfOneTimeKeys returns the largest number of one time keys this
// Account can store.
func (a *Account) MaxNumberOfOneTimeKeys() uint {
	return uint(account.MaxOneTimeKeys)
}

// GenOneTimeKeys generates a number of new one time keys.  If the total number
// of keys stored by this Account exceeds MaxNumberOfOneTimeKeys then the old
// keys are discarded.
func (a *Account) GenOneTimeKeys(num uint) {
	err := a.Account.GenOneTimeKeys(nil, num)
	if err != nil {
		panic(err)
	}
}

// NewOutboundSession creates a new out-bound session for sending messages to a
// given curve25519 identityKey and oneTimeKey. Returns error on failure.
func (a *Account) NewOutboundSession(theirIdentityKey, theirOneTimeKey id.Curve25519) (*Session, error) {
	if len(theirIdentityKey) == 0 || len(theirOneTimeKey) == 0 {
		return nil, EmptyInput
	}
	s := &Session{}
	newSession, err := a.Account.NewOutboundSession(theirIdentityKey, theirOneTimeKey)
	if err != nil {
		return nil, err
	}
	s.OlmSession = *newSession
	return s, nil
}

// NewInboundSession creates a new in-bound session for sending/receiving
// messages from an incoming PRE_KEY message. Returns error on failure.
func (a *Account) NewInboundSession(oneTimeKeyMsg string) (*Session, error) {
	if len(oneTimeKeyMsg) == 0 {
		return nil, EmptyInput
	}
	s := &Session{}
	newSession, err := a.Account.NewInboundSession(nil, []byte(oneTimeKeyMsg))
	if err != nil {
		return nil, err
	}
	s.OlmSession = *newSession
	return s, nil
}

// NewInboundSessionFrom creates a new in-bound session for sending/receiving
// messages from an incoming PRE_KEY message. Returns error on failure.
func (a *Account) NewInboundSessionFrom(theirIdentityKey id.Curve25519, oneTimeKeyMsg string) (*Session, error) {
	if len(theirIdentityKey) == 0 || len(oneTimeKeyMsg) == 0 {
		return nil, EmptyInput
	}
	s := &Session{}
	newSession, err := a.Account.NewInboundSession(&theirIdentityKey, []byte(oneTimeKeyMsg))
	if err != nil {
		return nil, err
	}
	s.OlmSession = *newSession
	return s, nil
}

// RemoveOneTimeKeys removes the one time keys that the session used from the
// Account. Returns error on failure.
func (a *Account) RemoveOneTimeKeys(s *Session) error {
	a.Account.RemoveOneTimeKeys(&s.OlmSession)
	return nil
}
