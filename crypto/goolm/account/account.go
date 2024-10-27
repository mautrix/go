// account packages an account which stores the identity, one time keys and fallback keys.
package account

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"maunium.net/go/mautrix/id"

	"maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/crypto/goolm/libolmpickle"
	"maunium.net/go/mautrix/crypto/goolm/session"
	"maunium.net/go/mautrix/crypto/olm"
)

const (
	accountPickleVersionJSON   byte   = 1
	accountPickleVersionLibOLM uint32 = 4
	MaxOneTimeKeys             int    = 100 //maximum number of stored one time keys per Account
)

// Account stores an account for end to end encrypted messaging via the olm protocol.
// An Account can not be used to en/decrypt messages. However it can be used to contruct new olm sessions, which in turn do the en/decryption.
// There is no tracking of sessions in an account.
type Account struct {
	IdKeys struct {
		Ed25519    crypto.Ed25519KeyPair    `json:"ed25519,omitempty"`
		Curve25519 crypto.Curve25519KeyPair `json:"curve25519,omitempty"`
	} `json:"identity_keys"`
	OTKeys             []crypto.OneTimeKey `json:"one_time_keys"`
	CurrentFallbackKey crypto.OneTimeKey   `json:"current_fallback_key,omitempty"`
	PrevFallbackKey    crypto.OneTimeKey   `json:"prev_fallback_key,omitempty"`
	NextOneTimeKeyID   uint32              `json:"next_one_time_key_id,omitempty"`
	NumFallbackKeys    uint8               `json:"number_fallback_keys"`
}

// Ensure that Account adheres to the olm.Account interface.
var _ olm.Account = (*Account)(nil)

// AccountFromJSONPickled loads the Account details from a pickled base64 string. The input is decrypted with the supplied key.
func AccountFromJSONPickled(pickled, key []byte) (*Account, error) {
	if len(pickled) == 0 {
		return nil, fmt.Errorf("accountFromPickled: %w", olm.ErrEmptyInput)
	}
	a := &Account{}
	return a, a.UnpickleAsJSON(pickled, key)
}

// AccountFromPickled loads the Account details from a pickled base64 string. The input is decrypted with the supplied key.
func AccountFromPickled(pickled, key []byte) (*Account, error) {
	if len(pickled) == 0 {
		return nil, fmt.Errorf("accountFromPickled: %w", olm.ErrEmptyInput)
	}
	a := &Account{}
	return a, a.Unpickle(pickled, key)
}

// NewAccount creates a new Account.
func NewAccount() (*Account, error) {
	a := &Account{}
	kPEd25519, err := crypto.Ed25519GenerateKey()
	if err != nil {
		return nil, err
	}
	a.IdKeys.Ed25519 = kPEd25519
	kPCurve25519, err := crypto.Curve25519GenerateKey()
	if err != nil {
		return nil, err
	}
	a.IdKeys.Curve25519 = kPCurve25519
	return a, nil
}

// PickleAsJSON returns an Account as a base64 string encrypted using the supplied key. The unencrypted representation of the Account is in JSON format.
func (a *Account) PickleAsJSON(key []byte) ([]byte, error) {
	return libolmpickle.PickleAsJSON(a, accountPickleVersionJSON, key)
}

// UnpickleAsJSON updates an Account by a base64 encrypted string using the supplied key. The unencrypted representation has to be in JSON format.
func (a *Account) UnpickleAsJSON(pickled, key []byte) error {
	return libolmpickle.UnpickleAsJSON(a, pickled, key, accountPickleVersionJSON)
}

// IdentityKeysJSON returns the public parts of the identity keys for the Account in a JSON string.
func (a *Account) IdentityKeysJSON() ([]byte, error) {
	res := struct {
		Ed25519    string `json:"ed25519"`
		Curve25519 string `json:"curve25519"`
	}{}
	ed25519, curve25519, err := a.IdentityKeys()
	if err != nil {
		return nil, err
	}
	res.Ed25519 = string(ed25519)
	res.Curve25519 = string(curve25519)
	return json.Marshal(res)
}

// IdentityKeys returns the public parts of the Ed25519 and Curve25519 identity keys for the Account.
func (a *Account) IdentityKeys() (id.Ed25519, id.Curve25519, error) {
	ed25519 := id.Ed25519(base64.RawStdEncoding.EncodeToString(a.IdKeys.Ed25519.PublicKey))
	curve25519 := id.Curve25519(base64.RawStdEncoding.EncodeToString(a.IdKeys.Curve25519.PublicKey))
	return ed25519, curve25519, nil
}

// Sign returns the base64-encoded signature of a message using the Ed25519 key
// for this Account.
func (a *Account) Sign(message []byte) ([]byte, error) {
	if len(message) == 0 {
		return nil, fmt.Errorf("sign: %w", olm.ErrEmptyInput)
	} else if signature, err := a.IdKeys.Ed25519.Sign(message); err != nil {
		return nil, err
	} else {
		return []byte(base64.RawStdEncoding.EncodeToString(signature)), nil
	}
}

// OneTimeKeys returns the public parts of the unpublished one time keys of the Account.
//
// The returned data is a map with the mapping of key id to base64-encoded Curve25519 key.
func (a *Account) OneTimeKeys() (map[string]id.Curve25519, error) {
	oneTimeKeys := make(map[string]id.Curve25519)
	for _, curKey := range a.OTKeys {
		if !curKey.Published {
			oneTimeKeys[curKey.KeyIDEncoded()] = curKey.Key.PublicKey.B64Encoded()
		}
	}
	return oneTimeKeys, nil
}

// MarkKeysAsPublished marks the current set of one time keys and the fallback key as being
// published.
func (a *Account) MarkKeysAsPublished() {
	for keyIndex := range a.OTKeys {
		if !a.OTKeys[keyIndex].Published {
			a.OTKeys[keyIndex].Published = true
		}
	}
	a.CurrentFallbackKey.Published = true
}

// GenOneTimeKeys generates a number of new one time keys. If the total number
// of keys stored by this Account exceeds MaxOneTimeKeys then the older
// keys are discarded.
func (a *Account) GenOneTimeKeys(num uint) error {
	for i := uint(0); i < num; i++ {
		key := crypto.OneTimeKey{
			Published: false,
			ID:        a.NextOneTimeKeyID,
		}
		newKP, err := crypto.Curve25519GenerateKey()
		if err != nil {
			return err
		}
		key.Key = newKP
		a.NextOneTimeKeyID++
		a.OTKeys = append([]crypto.OneTimeKey{key}, a.OTKeys...)
	}
	if len(a.OTKeys) > MaxOneTimeKeys {
		a.OTKeys = a.OTKeys[:MaxOneTimeKeys]
	}
	return nil
}

// NewOutboundSession creates a new outbound session to a
// given curve25519 identity Key and one time key.
func (a *Account) NewOutboundSession(theirIdentityKey, theirOneTimeKey id.Curve25519) (olm.Session, error) {
	if len(theirIdentityKey) == 0 || len(theirOneTimeKey) == 0 {
		return nil, fmt.Errorf("outbound session: %w", olm.ErrEmptyInput)
	}
	theirIdentityKeyDecoded, err := base64.RawStdEncoding.DecodeString(string(theirIdentityKey))
	if err != nil {
		return nil, err
	}
	theirOneTimeKeyDecoded, err := base64.RawStdEncoding.DecodeString(string(theirOneTimeKey))
	if err != nil {
		return nil, err
	}
	return session.NewOutboundOlmSession(a.IdKeys.Curve25519, theirIdentityKeyDecoded, theirOneTimeKeyDecoded)
}

// NewInboundSession creates a new in-bound session for sending/receiving
// messages from an incoming PRE_KEY message. Returns error on failure.
func (a *Account) NewInboundSession(oneTimeKeyMsg string) (olm.Session, error) {
	return a.NewInboundSessionFrom(nil, oneTimeKeyMsg)
}

// NewInboundSessionFrom creates a new inbound session from an incoming PRE_KEY message.
func (a *Account) NewInboundSessionFrom(theirIdentityKey *id.Curve25519, oneTimeKeyMsg string) (olm.Session, error) {
	if len(oneTimeKeyMsg) == 0 {
		return nil, fmt.Errorf("inbound session: %w", olm.ErrEmptyInput)
	}
	var theirIdentityKeyDecoded *crypto.Curve25519PublicKey
	if theirIdentityKey != nil {
		theirIdentityKeyDecodedByte, err := base64.RawStdEncoding.DecodeString(string(*theirIdentityKey))
		if err != nil {
			return nil, err
		}
		theirIdentityKeyCurve := crypto.Curve25519PublicKey(theirIdentityKeyDecodedByte)
		theirIdentityKeyDecoded = &theirIdentityKeyCurve
	}

	return session.NewInboundOlmSession(theirIdentityKeyDecoded, []byte(oneTimeKeyMsg), a.searchOTKForOur, a.IdKeys.Curve25519)
}

func (a *Account) searchOTKForOur(toFind crypto.Curve25519PublicKey) *crypto.OneTimeKey {
	for curIndex := range a.OTKeys {
		if a.OTKeys[curIndex].Key.PublicKey.Equal(toFind) {
			return &a.OTKeys[curIndex]
		}
	}
	if a.NumFallbackKeys >= 1 && a.CurrentFallbackKey.Key.PublicKey.Equal(toFind) {
		return &a.CurrentFallbackKey
	}
	if a.NumFallbackKeys >= 2 && a.PrevFallbackKey.Key.PublicKey.Equal(toFind) {
		return &a.PrevFallbackKey
	}
	return nil
}

// RemoveOneTimeKeys removes the one time key in this Account which matches the one time key in the session s.
func (a *Account) RemoveOneTimeKeys(s olm.Session) error {
	toFind := s.(*session.OlmSession).BobOneTimeKey
	for curIndex := range a.OTKeys {
		if a.OTKeys[curIndex].Key.PublicKey.Equal(toFind) {
			//Remove and return
			a.OTKeys[curIndex] = a.OTKeys[len(a.OTKeys)-1]
			a.OTKeys = a.OTKeys[:len(a.OTKeys)-1]
			return nil
		}
	}
	return nil
	//if the key is a fallback or prevFallback, don't remove it
}

// GenFallbackKey generates a new fallback key. The old fallback key is stored
// in a.PrevFallbackKey overwriting any previous PrevFallbackKey.
func (a *Account) GenFallbackKey() error {
	a.PrevFallbackKey = a.CurrentFallbackKey
	key := crypto.OneTimeKey{
		Published: false,
		ID:        a.NextOneTimeKeyID,
	}
	newKP, err := crypto.Curve25519GenerateKey()
	if err != nil {
		return err
	}
	key.Key = newKP
	a.NextOneTimeKeyID++
	if a.NumFallbackKeys < 2 {
		a.NumFallbackKeys++
	}
	a.CurrentFallbackKey = key
	return nil
}

// FallbackKey returns the public part of the current fallback key of the Account.
// The returned data is a map with the mapping of key id to base64-encoded Curve25519 key.
func (a *Account) FallbackKey() map[string]id.Curve25519 {
	keys := make(map[string]id.Curve25519)
	if a.NumFallbackKeys >= 1 {
		keys[a.CurrentFallbackKey.KeyIDEncoded()] = a.CurrentFallbackKey.Key.PublicKey.B64Encoded()
	}
	return keys
}

//FallbackKeyJSON returns the public part of the current fallback key of the Account as a JSON string.
//
//The returned JSON is of format:
/*
	{
	    curve25519: {
	        "AAAAAA": "wo76WcYtb0Vk/pBOdmduiGJ0wIEjW4IBMbbQn7aSnTo"
	    }
	}
*/
func (a *Account) FallbackKeyJSON() ([]byte, error) {
	res := make(map[string]map[string]id.Curve25519)
	fbk := a.FallbackKey()
	res["curve25519"] = fbk
	return json.Marshal(res)
}

// FallbackKeyUnpublished returns the public part of the current fallback key of the Account only if it is unpublished.
// The returned data is a map with the mapping of key id to base64-encoded Curve25519 key.
func (a *Account) FallbackKeyUnpublished() map[string]id.Curve25519 {
	keys := make(map[string]id.Curve25519)
	if a.NumFallbackKeys >= 1 && !a.CurrentFallbackKey.Published {
		keys[a.CurrentFallbackKey.KeyIDEncoded()] = a.CurrentFallbackKey.Key.PublicKey.B64Encoded()
	}
	return keys
}

//FallbackKeyUnpublishedJSON returns the public part of the current fallback key, only if it is unpublished, of the Account as a JSON string.
//
//The returned JSON is of format:
/*
	{
	    curve25519: {
	        "AAAAAA": "wo76WcYtb0Vk/pBOdmduiGJ0wIEjW4IBMbbQn7aSnTo"
	    }
	}
*/
func (a *Account) FallbackKeyUnpublishedJSON() ([]byte, error) {
	res := make(map[string]map[string]id.Curve25519)
	fbk := a.FallbackKeyUnpublished()
	res["curve25519"] = fbk
	return json.Marshal(res)
}

// ForgetOldFallbackKey resets the previous fallback key in the account.
func (a *Account) ForgetOldFallbackKey() {
	if a.NumFallbackKeys >= 2 {
		a.NumFallbackKeys = 1
		a.PrevFallbackKey = crypto.OneTimeKey{}
	}
}

// Unpickle decodes the base64 encoded string and decrypts the result with the key.
// The decrypted value is then passed to UnpickleLibOlm.
func (a *Account) Unpickle(pickled, key []byte) error {
	decrypted, err := libolmpickle.Unpickle(key, pickled)
	if err != nil {
		return err
	}
	return a.UnpickleLibOlm(decrypted)
}

// UnpickleLibOlm unpickles the unencryted value and populates the [Account] accordingly.
func (a *Account) UnpickleLibOlm(buf []byte) error {
	decoder := libolmpickle.NewDecoder(buf)
	pickledVersion, err := decoder.ReadUInt32()
	if err != nil {
		return err
	} else if pickledVersion != accountPickleVersionLibOLM && pickledVersion != 3 && pickledVersion != 2 {
		return fmt.Errorf("unpickle account: %w (found version %d)", olm.ErrBadVersion, pickledVersion)
	} else if err = a.IdKeys.Ed25519.UnpickleLibOlm(decoder); err != nil { // read the ed25519 key pair
		return err
	} else if err = a.IdKeys.Curve25519.UnpickleLibOlm(decoder); err != nil { // read curve25519 key pair
		return err
	}

	otkCount, err := decoder.ReadUInt32()
	if err != nil {
		return err
	}

	a.OTKeys = make([]crypto.OneTimeKey, otkCount)
	for i := uint32(0); i < otkCount; i++ {
		if err := a.OTKeys[i].UnpickleLibOlm(decoder); err != nil {
			return err
		}
	}

	if pickledVersion <= 2 {
		// version 2 did not have fallback keys
		a.NumFallbackKeys = 0
	} else if pickledVersion == 3 {
		// version 3 used the published flag to indicate how many fallback keys
		// were present (we'll have to assume that the keys were published)
		if err = a.CurrentFallbackKey.UnpickleLibOlm(decoder); err != nil {
			return err
		} else if err = a.PrevFallbackKey.UnpickleLibOlm(decoder); err != nil {
			return err
		}
		if a.CurrentFallbackKey.Published {
			if a.PrevFallbackKey.Published {
				a.NumFallbackKeys = 2
			} else {
				a.NumFallbackKeys = 1
			}
		} else {
			a.NumFallbackKeys = 0
		}
	} else {
		// Read number of fallback keys
		a.NumFallbackKeys, err = decoder.ReadUInt8()
		if err != nil {
			return err
		}
		for i := 0; i < int(a.NumFallbackKeys); i++ {
			switch i {
			case 0:
				if err = a.CurrentFallbackKey.UnpickleLibOlm(decoder); err != nil {
					return err
				}
			case 1:
				if err = a.PrevFallbackKey.UnpickleLibOlm(decoder); err != nil {
					return err
				}
			default:
				// Just drain any remaining fallback keys
				if err = (&crypto.OneTimeKey{}).UnpickleLibOlm(decoder); err != nil {
					return err
				}
			}
		}
	}

	//Read next onetime key ID
	a.NextOneTimeKeyID, err = decoder.ReadUInt32()
	return err
}

// Pickle returns a base64 encoded and with key encrypted pickled account using PickleLibOlm().
func (a *Account) Pickle(key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, olm.ErrNoKeyProvided
	}
	return libolmpickle.Pickle(key, a.PickleLibOlm())
}

// PickleLibOlm pickles the [Account] and returns the raw bytes.
func (a *Account) PickleLibOlm() []byte {
	encoder := libolmpickle.NewEncoder()
	encoder.WriteUInt32(accountPickleVersionLibOLM)
	a.IdKeys.Ed25519.PickleLibOlm(encoder)
	a.IdKeys.Curve25519.PickleLibOlm(encoder)

	// One-Time Keys
	encoder.WriteUInt32(uint32(len(a.OTKeys)))
	for _, curOTKey := range a.OTKeys {
		curOTKey.PickleLibOlm(encoder)
	}

	// Fallback Keys
	encoder.WriteUInt8(a.NumFallbackKeys)
	if a.NumFallbackKeys >= 1 {
		a.CurrentFallbackKey.PickleLibOlm(encoder)
		if a.NumFallbackKeys >= 2 {
			a.PrevFallbackKey.PickleLibOlm(encoder)
		}
	}
	encoder.WriteUInt32(a.NextOneTimeKeyID)
	return encoder.Bytes()
}

// MaxNumberOfOneTimeKeys returns the largest number of one time keys this
// Account can store.
func (a *Account) MaxNumberOfOneTimeKeys() uint {
	return uint(MaxOneTimeKeys)
}
