// account packages an account which stores the identity, one time keys and fallback keys.
package account

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/element-hq/mautrix-go/id"

	"github.com/element-hq/mautrix-go/crypto/goolm"
	"github.com/element-hq/mautrix-go/crypto/goolm/cipher"
	"github.com/element-hq/mautrix-go/crypto/goolm/crypto"
	"github.com/element-hq/mautrix-go/crypto/goolm/libolmpickle"
	"github.com/element-hq/mautrix-go/crypto/goolm/session"
	"github.com/element-hq/mautrix-go/crypto/goolm/utilities"
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

// AccountFromJSONPickled loads the Account details from a pickled base64 string. The input is decrypted with the supplied key.
func AccountFromJSONPickled(pickled, key []byte) (*Account, error) {
	if len(pickled) == 0 {
		return nil, fmt.Errorf("accountFromPickled: %w", goolm.ErrEmptyInput)
	}
	a := &Account{}
	err := a.UnpickleAsJSON(pickled, key)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// AccountFromPickled loads the Account details from a pickled base64 string. The input is decrypted with the supplied key.
func AccountFromPickled(pickled, key []byte) (*Account, error) {
	if len(pickled) == 0 {
		return nil, fmt.Errorf("accountFromPickled: %w", goolm.ErrEmptyInput)
	}
	a := &Account{}
	err := a.Unpickle(pickled, key)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// NewAccount creates a new Account. If reader is nil, crypto/rand is used for the key creation.
func NewAccount(reader io.Reader) (*Account, error) {
	a := &Account{}
	kPEd25519, err := crypto.Ed25519GenerateKey(reader)
	if err != nil {
		return nil, err
	}
	a.IdKeys.Ed25519 = kPEd25519
	kPCurve25519, err := crypto.Curve25519GenerateKey(reader)
	if err != nil {
		return nil, err
	}
	a.IdKeys.Curve25519 = kPCurve25519
	return a, nil
}

// PickleAsJSON returns an Account as a base64 string encrypted using the supplied key. The unencrypted representation of the Account is in JSON format.
func (a Account) PickleAsJSON(key []byte) ([]byte, error) {
	return utilities.PickleAsJSON(a, accountPickleVersionJSON, key)
}

// UnpickleAsJSON updates an Account by a base64 encrypted string using the supplied key. The unencrypted representation has to be in JSON format.
func (a *Account) UnpickleAsJSON(pickled, key []byte) error {
	return utilities.UnpickleAsJSON(a, pickled, key, accountPickleVersionJSON)
}

// IdentityKeysJSON returns the public parts of the identity keys for the Account in a JSON string.
func (a Account) IdentityKeysJSON() ([]byte, error) {
	res := struct {
		Ed25519    string `json:"ed25519"`
		Curve25519 string `json:"curve25519"`
	}{}
	ed25519, curve25519 := a.IdentityKeys()
	res.Ed25519 = string(ed25519)
	res.Curve25519 = string(curve25519)
	return json.Marshal(res)
}

// IdentityKeys returns the public parts of the Ed25519 and Curve25519 identity keys for the Account.
func (a Account) IdentityKeys() (id.Ed25519, id.Curve25519) {
	ed25519 := id.Ed25519(base64.RawStdEncoding.EncodeToString(a.IdKeys.Ed25519.PublicKey))
	curve25519 := id.Curve25519(base64.RawStdEncoding.EncodeToString(a.IdKeys.Curve25519.PublicKey))
	return ed25519, curve25519
}

// Sign returns the base64-encoded signature of a message using the Ed25519 key
// for this Account.
func (a Account) Sign(message []byte) ([]byte, error) {
	if len(message) == 0 {
		return nil, fmt.Errorf("sign: %w", goolm.ErrEmptyInput)
	}
	return []byte(base64.RawStdEncoding.EncodeToString(a.IdKeys.Ed25519.Sign(message))), nil
}

// OneTimeKeys returns the public parts of the unpublished one time keys of the Account.
//
// The returned data is a map with the mapping of key id to base64-encoded Curve25519 key.
func (a Account) OneTimeKeys() map[string]id.Curve25519 {
	oneTimeKeys := make(map[string]id.Curve25519)
	for _, curKey := range a.OTKeys {
		if !curKey.Published {
			oneTimeKeys[curKey.KeyIDEncoded()] = id.Curve25519(curKey.PublicKeyEncoded())
		}
	}
	return oneTimeKeys
}

//OneTimeKeysJSON returns the public parts of the unpublished one time keys of the Account as a JSON string.
//
//The returned JSON is of format:
/*
	{
	    Curve25519: {
	        "AAAAAA": "wo76WcYtb0Vk/pBOdmduiGJ0wIEjW4IBMbbQn7aSnTo",
	        "AAAAAB": "LRvjo46L1X2vx69sS9QNFD29HWulxrmW11Up5AfAjgU"
	    }
	}
*/
func (a Account) OneTimeKeysJSON() ([]byte, error) {
	res := make(map[string]map[string]id.Curve25519)
	otKeys := a.OneTimeKeys()
	res["Curve25519"] = otKeys
	return json.Marshal(res)
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
// keys are discarded. If reader is nil, crypto/rand is used for the key creation.
func (a *Account) GenOneTimeKeys(reader io.Reader, num uint) error {
	for i := uint(0); i < num; i++ {
		key := crypto.OneTimeKey{
			Published: false,
			ID:        a.NextOneTimeKeyID,
		}
		newKP, err := crypto.Curve25519GenerateKey(reader)
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
func (a Account) NewOutboundSession(theirIdentityKey, theirOneTimeKey id.Curve25519) (*session.OlmSession, error) {
	if len(theirIdentityKey) == 0 || len(theirOneTimeKey) == 0 {
		return nil, fmt.Errorf("outbound session: %w", goolm.ErrEmptyInput)
	}
	theirIdentityKeyDecoded, err := base64.RawStdEncoding.DecodeString(string(theirIdentityKey))
	if err != nil {
		return nil, err
	}
	theirOneTimeKeyDecoded, err := base64.RawStdEncoding.DecodeString(string(theirOneTimeKey))
	if err != nil {
		return nil, err
	}
	s, err := session.NewOutboundOlmSession(a.IdKeys.Curve25519, theirIdentityKeyDecoded, theirOneTimeKeyDecoded)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// NewInboundSession creates a new inbound session from an incoming PRE_KEY message.
func (a Account) NewInboundSession(theirIdentityKey *id.Curve25519, oneTimeKeyMsg []byte) (*session.OlmSession, error) {
	if len(oneTimeKeyMsg) == 0 {
		return nil, fmt.Errorf("inbound session: %w", goolm.ErrEmptyInput)
	}
	var theirIdentityKeyDecoded *crypto.Curve25519PublicKey
	var err error
	if theirIdentityKey != nil {
		theirIdentityKeyDecodedByte, err := base64.RawStdEncoding.DecodeString(string(*theirIdentityKey))
		if err != nil {
			return nil, err
		}
		theirIdentityKeyCurve := crypto.Curve25519PublicKey(theirIdentityKeyDecodedByte)
		theirIdentityKeyDecoded = &theirIdentityKeyCurve
	}

	s, err := session.NewInboundOlmSession(theirIdentityKeyDecoded, oneTimeKeyMsg, a.searchOTKForOur, a.IdKeys.Curve25519)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (a Account) searchOTKForOur(toFind crypto.Curve25519PublicKey) *crypto.OneTimeKey {
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
func (a *Account) RemoveOneTimeKeys(s *session.OlmSession) {
	toFind := s.BobOneTimeKey
	for curIndex := range a.OTKeys {
		if a.OTKeys[curIndex].Key.PublicKey.Equal(toFind) {
			//Remove and return
			a.OTKeys[curIndex] = a.OTKeys[len(a.OTKeys)-1]
			a.OTKeys = a.OTKeys[:len(a.OTKeys)-1]
			return
		}
	}
	//if the key is a fallback or prevFallback, don't remove it
}

// GenFallbackKey generates a new fallback key. The old fallback key is stored in a.PrevFallbackKey overwriting any previous PrevFallbackKey. If reader is nil, crypto/rand is used for the key creation.
func (a *Account) GenFallbackKey(reader io.Reader) error {
	a.PrevFallbackKey = a.CurrentFallbackKey
	key := crypto.OneTimeKey{
		Published: false,
		ID:        a.NextOneTimeKeyID,
	}
	newKP, err := crypto.Curve25519GenerateKey(reader)
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
func (a Account) FallbackKey() map[string]id.Curve25519 {
	keys := make(map[string]id.Curve25519)
	if a.NumFallbackKeys >= 1 {
		keys[a.CurrentFallbackKey.KeyIDEncoded()] = id.Curve25519(a.CurrentFallbackKey.PublicKeyEncoded())
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
func (a Account) FallbackKeyJSON() ([]byte, error) {
	res := make(map[string]map[string]id.Curve25519)
	fbk := a.FallbackKey()
	res["curve25519"] = fbk
	return json.Marshal(res)
}

// FallbackKeyUnpublished returns the public part of the current fallback key of the Account only if it is unpublished.
// The returned data is a map with the mapping of key id to base64-encoded Curve25519 key.
func (a Account) FallbackKeyUnpublished() map[string]id.Curve25519 {
	keys := make(map[string]id.Curve25519)
	if a.NumFallbackKeys >= 1 && !a.CurrentFallbackKey.Published {
		keys[a.CurrentFallbackKey.KeyIDEncoded()] = id.Curve25519(a.CurrentFallbackKey.PublicKeyEncoded())
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
func (a Account) FallbackKeyUnpublishedJSON() ([]byte, error) {
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
	decrypted, err := cipher.Unpickle(key, pickled)
	if err != nil {
		return err
	}
	_, err = a.UnpickleLibOlm(decrypted)
	return err
}

// UnpickleLibOlm decodes the unencryted value and populates the Account accordingly. It returns the number of bytes read.
func (a *Account) UnpickleLibOlm(value []byte) (int, error) {
	//First 4 bytes are the accountPickleVersion
	pickledVersion, curPos, err := libolmpickle.UnpickleUInt32(value)
	if err != nil {
		return 0, err
	}
	switch pickledVersion {
	case accountPickleVersionLibOLM, 3, 2:
	default:
		return 0, fmt.Errorf("unpickle account: %w", goolm.ErrBadVersion)
	}
	//read ed25519 key pair
	readBytes, err := a.IdKeys.Ed25519.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	//read curve25519 key pair
	readBytes, err = a.IdKeys.Curve25519.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	//Read number of onetimeKeys
	numberOTKeys, readBytes, err := libolmpickle.UnpickleUInt32(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	//Read i one time keys
	a.OTKeys = make([]crypto.OneTimeKey, numberOTKeys)
	for i := uint32(0); i < numberOTKeys; i++ {
		readBytes, err := a.OTKeys[i].UnpickleLibOlm(value[curPos:])
		if err != nil {
			return 0, err
		}
		curPos += readBytes
	}
	if pickledVersion <= 2 {
		// version 2 did not have fallback keys
		a.NumFallbackKeys = 0
	} else if pickledVersion == 3 {
		// version 3 used the published flag to indicate how many fallback keys
		// were present (we'll have to assume that the keys were published)
		readBytes, err := a.CurrentFallbackKey.UnpickleLibOlm(value[curPos:])
		if err != nil {
			return 0, err
		}
		curPos += readBytes
		readBytes, err = a.PrevFallbackKey.UnpickleLibOlm(value[curPos:])
		if err != nil {
			return 0, err
		}
		curPos += readBytes
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
		//Read number of fallback keys
		numFallbackKeys, readBytes, err := libolmpickle.UnpickleUInt8(value[curPos:])
		if err != nil {
			return 0, err
		}
		curPos += readBytes
		a.NumFallbackKeys = numFallbackKeys
		if a.NumFallbackKeys >= 1 {
			readBytes, err := a.CurrentFallbackKey.UnpickleLibOlm(value[curPos:])
			if err != nil {
				return 0, err
			}
			curPos += readBytes
			if a.NumFallbackKeys >= 2 {
				readBytes, err := a.PrevFallbackKey.UnpickleLibOlm(value[curPos:])
				if err != nil {
					return 0, err
				}
				curPos += readBytes
			}
		}
	}
	//Read next onetime key id
	nextOTKeyID, readBytes, err := libolmpickle.UnpickleUInt32(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	a.NextOneTimeKeyID = nextOTKeyID
	return curPos, nil
}

// Pickle returns a base64 encoded and with key encrypted pickled account using PickleLibOlm().
func (a Account) Pickle(key []byte) ([]byte, error) {
	pickeledBytes := make([]byte, a.PickleLen())
	written, err := a.PickleLibOlm(pickeledBytes)
	if err != nil {
		return nil, err
	}
	if written != len(pickeledBytes) {
		return nil, errors.New("number of written bytes not correct")
	}
	encrypted, err := cipher.Pickle(key, pickeledBytes)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

// PickleLibOlm encodes the Account into target. target has to have a size of at least PickleLen() and is written to from index 0.
// It returns the number of bytes written.
func (a Account) PickleLibOlm(target []byte) (int, error) {
	if len(target) < a.PickleLen() {
		return 0, fmt.Errorf("pickle account: %w", goolm.ErrValueTooShort)
	}
	written := libolmpickle.PickleUInt32(accountPickleVersionLibOLM, target)
	writtenEdKey, err := a.IdKeys.Ed25519.PickleLibOlm(target[written:])
	if err != nil {
		return 0, fmt.Errorf("pickle account: %w", err)
	}
	written += writtenEdKey
	writtenCurveKey, err := a.IdKeys.Curve25519.PickleLibOlm(target[written:])
	if err != nil {
		return 0, fmt.Errorf("pickle account: %w", err)
	}
	written += writtenCurveKey
	written += libolmpickle.PickleUInt32(uint32(len(a.OTKeys)), target[written:])
	for _, curOTKey := range a.OTKeys {
		writtenOT, err := curOTKey.PickleLibOlm(target[written:])
		if err != nil {
			return 0, fmt.Errorf("pickle account: %w", err)
		}
		written += writtenOT
	}
	written += libolmpickle.PickleUInt8(a.NumFallbackKeys, target[written:])
	if a.NumFallbackKeys >= 1 {
		writtenOT, err := a.CurrentFallbackKey.PickleLibOlm(target[written:])
		if err != nil {
			return 0, fmt.Errorf("pickle account: %w", err)
		}
		written += writtenOT

		if a.NumFallbackKeys >= 2 {
			writtenOT, err := a.PrevFallbackKey.PickleLibOlm(target[written:])
			if err != nil {
				return 0, fmt.Errorf("pickle account: %w", err)
			}
			written += writtenOT
		}
	}
	written += libolmpickle.PickleUInt32(a.NextOneTimeKeyID, target[written:])
	return written, nil
}

// PickleLen returns the number of bytes the pickled Account will have.
func (a Account) PickleLen() int {
	length := libolmpickle.PickleUInt32Len(accountPickleVersionLibOLM)
	length += a.IdKeys.Ed25519.PickleLen()
	length += a.IdKeys.Curve25519.PickleLen()
	length += libolmpickle.PickleUInt32Len(uint32(len(a.OTKeys)))
	length += (len(a.OTKeys) * (&crypto.OneTimeKey{}).PickleLen())
	length += libolmpickle.PickleUInt8Len(a.NumFallbackKeys)
	length += (int(a.NumFallbackKeys) * (&crypto.OneTimeKey{}).PickleLen())
	length += libolmpickle.PickleUInt32Len(a.NextOneTimeKeyID)
	return length
}
