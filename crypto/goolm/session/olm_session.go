package session

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/crypto/goolm/goolmbase64"
	"maunium.net/go/mautrix/crypto/goolm/libolmpickle"
	"maunium.net/go/mautrix/crypto/goolm/message"
	"maunium.net/go/mautrix/crypto/goolm/ratchet"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/id"
)

const (
	olmSessionPickleVersionJSON   uint8  = 1
	olmSessionPickleVersionLibOlm uint32 = 1
)

const (
	protocolVersion = 0x3
)

// OlmSession stores all information for an olm session
type OlmSession struct {
	ReceivedMessage  bool                       `json:"received_message"`
	AliceIdentityKey crypto.Curve25519PublicKey `json:"alice_id_key"`
	AliceBaseKey     crypto.Curve25519PublicKey `json:"alice_base_key"`
	BobOneTimeKey    crypto.Curve25519PublicKey `json:"bob_one_time_key"`
	Ratchet          ratchet.Ratchet            `json:"ratchet"`
}

var _ olm.Session = (*OlmSession)(nil)

// SearchOTKFunc is used to retrieve a crypto.OneTimeKey from a public key.
type SearchOTKFunc = func(crypto.Curve25519PublicKey) *crypto.OneTimeKey

// OlmSessionFromJSONPickled loads an OlmSession from a pickled base64 string. Decrypts
// the Session using the supplied key.
func OlmSessionFromJSONPickled(pickled, key []byte) (*OlmSession, error) {
	if len(pickled) == 0 {
		return nil, fmt.Errorf("sessionFromPickled: %w", olm.ErrEmptyInput)
	}
	a := &OlmSession{}
	return a, a.UnpickleAsJSON(pickled, key)
}

// OlmSessionFromPickled loads the OlmSession details from a pickled base64 string. The input is decrypted with the supplied key.
func OlmSessionFromPickled(pickled, key []byte) (*OlmSession, error) {
	if len(pickled) == 0 {
		return nil, fmt.Errorf("sessionFromPickled: %w", olm.ErrEmptyInput)
	}
	a := &OlmSession{}
	return a, a.Unpickle(pickled, key)
}

// NewOlmSession creates a new Session.
func NewOlmSession() *OlmSession {
	s := &OlmSession{}
	s.Ratchet = *ratchet.New()
	return s
}

// NewOutboundOlmSession creates a new outbound session for sending the first message to a
// given curve25519 identityKey and oneTimeKey.
func NewOutboundOlmSession(identityKeyAlice crypto.Curve25519KeyPair, identityKeyBob crypto.Curve25519PublicKey, oneTimeKeyBob crypto.Curve25519PublicKey) (*OlmSession, error) {
	s := NewOlmSession()
	//generate E_A
	baseKey, err := crypto.Curve25519GenerateKey()
	if err != nil {
		return nil, err
	}
	//generate T_0
	ratchetKey, err := crypto.Curve25519GenerateKey()
	if err != nil {
		return nil, err
	}

	//Calculate shared secret via Triple Diffie-Hellman
	var secret []byte
	//ECDH(I_A,E_B)
	idSecret, err := identityKeyAlice.SharedSecret(oneTimeKeyBob)
	if err != nil {
		return nil, err
	}
	//ECDH(E_A,I_B)
	baseIdSecret, err := baseKey.SharedSecret(identityKeyBob)
	if err != nil {
		return nil, err
	}
	//ECDH(E_A,E_B)
	baseOneTimeSecret, err := baseKey.SharedSecret(oneTimeKeyBob)
	if err != nil {
		return nil, err
	}
	secret = append(secret, idSecret...)
	secret = append(secret, baseIdSecret...)
	secret = append(secret, baseOneTimeSecret...)
	//Init Ratchet
	s.Ratchet.InitializeAsAlice(secret, ratchetKey)
	s.AliceIdentityKey = identityKeyAlice.PublicKey
	s.AliceBaseKey = baseKey.PublicKey
	s.BobOneTimeKey = oneTimeKeyBob
	return s, nil
}

// NewInboundOlmSession creates a new inbound session from receiving the first message.
func NewInboundOlmSession(identityKeyAlice *crypto.Curve25519PublicKey, receivedOTKMsg []byte, searchBobOTK SearchOTKFunc, identityKeyBob crypto.Curve25519KeyPair) (*OlmSession, error) {
	decodedOTKMsg, err := goolmbase64.Decode(receivedOTKMsg)
	if err != nil {
		return nil, err
	}
	s := NewOlmSession()

	//decode OneTimeKeyMessage
	oneTimeMsg := message.PreKeyMessage{}
	err = oneTimeMsg.Decode(decodedOTKMsg)
	if err != nil {
		return nil, fmt.Errorf("OneTimeKeyMessage decode: %w", err)
	}
	if !oneTimeMsg.CheckFields(identityKeyAlice) {
		return nil, fmt.Errorf("OneTimeKeyMessage check fields: %w", olm.ErrBadMessageFormat)
	}

	//Either the identityKeyAlice is set and/or the oneTimeMsg.IdentityKey is set, which is checked
	// by oneTimeMsg.CheckFields
	if identityKeyAlice != nil && len(oneTimeMsg.IdentityKey) != 0 {
		//if both are set, compare them
		if !identityKeyAlice.Equal(oneTimeMsg.IdentityKey) {
			return nil, fmt.Errorf("OneTimeKeyMessage identity keys: %w", olm.ErrBadMessageKeyID)
		}
	}
	if identityKeyAlice == nil {
		//for downstream use set
		identityKeyAlice = &oneTimeMsg.IdentityKey
	}

	oneTimeKeyBob := searchBobOTK(oneTimeMsg.OneTimeKey)
	if oneTimeKeyBob == nil {
		return nil, fmt.Errorf("ourOneTimeKey: %w", olm.ErrBadMessageKeyID)
	}

	//Calculate shared secret via Triple Diffie-Hellman
	var secret []byte
	//ECDH(E_B,I_A)
	idSecret, err := oneTimeKeyBob.Key.SharedSecret(*identityKeyAlice)
	if err != nil {
		return nil, err
	}
	//ECDH(I_B,E_A)
	baseIdSecret, err := identityKeyBob.SharedSecret(oneTimeMsg.BaseKey)
	if err != nil {
		return nil, err
	}
	//ECDH(E_B,E_A)
	baseOneTimeSecret, err := oneTimeKeyBob.Key.SharedSecret(oneTimeMsg.BaseKey)
	if err != nil {
		return nil, err
	}
	secret = append(secret, idSecret...)
	secret = append(secret, baseIdSecret...)
	secret = append(secret, baseOneTimeSecret...)
	//decode message
	msg := message.Message{}
	err = msg.Decode(oneTimeMsg.Message)
	if err != nil {
		return nil, fmt.Errorf("Message decode: %w", err)
	}

	if len(msg.RatchetKey) == 0 {
		return nil, fmt.Errorf("Message missing ratchet key: %w", olm.ErrBadMessageFormat)
	}
	//Init Ratchet
	s.Ratchet.InitializeAsBob(secret, msg.RatchetKey)
	s.AliceBaseKey = oneTimeMsg.BaseKey
	s.AliceIdentityKey = oneTimeMsg.IdentityKey
	s.BobOneTimeKey = oneTimeKeyBob.Key.PublicKey

	//https://gitlab.matrix.org/matrix-org/olm/blob/master/docs/olm.md states to remove the oneTimeKey
	//this is done via the account itself
	return s, nil
}

// PickleAsJSON returns an Session as a base64 string encrypted using the supplied key. The unencrypted representation of the Account is in JSON format.
func (a OlmSession) PickleAsJSON(key []byte) ([]byte, error) {
	return libolmpickle.PickleAsJSON(a, olmSessionPickleVersionJSON, key)
}

// UnpickleAsJSON updates an Session by a base64 encrypted string with the key. The unencrypted representation has to be in JSON format.
func (a *OlmSession) UnpickleAsJSON(pickled, key []byte) error {
	return libolmpickle.UnpickleAsJSON(a, pickled, key, olmSessionPickleVersionJSON)
}

// ID returns an identifier for this Session.  Will be the same for both ends of the conversation.
// Generated by hashing the public keys used to create the session.
func (s *OlmSession) ID() id.SessionID {
	message := make([]byte, 3*crypto.Curve25519PrivateKeyLength)
	copy(message, s.AliceIdentityKey)
	copy(message[crypto.Curve25519PrivateKeyLength:], s.AliceBaseKey)
	copy(message[2*crypto.Curve25519PrivateKeyLength:], s.BobOneTimeKey)
	hash := sha256.Sum256(message)
	res := id.SessionID(goolmbase64.Encode(hash[:]))
	return res
}

// HasReceivedMessage returns true if this session has received any message.
func (s *OlmSession) HasReceivedMessage() bool {
	return s.ReceivedMessage
}

// MatchesInboundSession checks if the PRE_KEY message is for this in-bound
// Session. This can happen if multiple messages are sent to this Account
// before this Account sends a message in reply. Returns true if the session
// matches. Returns false if the session does not match. Returns error on
// failure.
func (s *OlmSession) MatchesInboundSession(oneTimeKeyMsg string) (bool, error) {
	return s.matchesInboundSession(nil, []byte(oneTimeKeyMsg))
}

// MatchesInboundSessionFrom checks if the PRE_KEY message is for this in-bound
// Session. This can happen if multiple messages are sent to this Account
// before this Account sends a message in reply. Returns true if the session
// matches. Returns false if the session does not match. Returns error on
// failure.
func (s *OlmSession) MatchesInboundSessionFrom(theirIdentityKey, oneTimeKeyMsg string) (bool, error) {
	var theirKey *id.Curve25519
	if theirIdentityKey != "" {
		theirs := id.Curve25519(theirIdentityKey)
		theirKey = &theirs
	}

	return s.matchesInboundSession(theirKey, []byte(oneTimeKeyMsg))
}

// matchesInboundSession checks if the oneTimeKeyMsg message is set for this
// inbound Session.  This can happen if multiple messages are sent to this
// Account before this Account sends a message in reply.  Returns true if the
// session matches.  Returns false if the session does not match.
func (s *OlmSession) matchesInboundSession(theirIdentityKeyEncoded *id.Curve25519, receivedOTKMsg []byte) (bool, error) {
	if len(receivedOTKMsg) == 0 {
		return false, fmt.Errorf("inbound match: %w", olm.ErrEmptyInput)
	}
	decodedOTKMsg, err := goolmbase64.Decode(receivedOTKMsg)
	if err != nil {
		return false, err
	}

	var theirIdentityKey *crypto.Curve25519PublicKey
	if theirIdentityKeyEncoded != nil {
		decodedKey, err := base64.RawStdEncoding.DecodeString(string(*theirIdentityKeyEncoded))
		if err != nil {
			return false, err
		}
		theirIdentityKeyByte := crypto.Curve25519PublicKey(decodedKey)
		theirIdentityKey = &theirIdentityKeyByte
	}

	msg := message.PreKeyMessage{}
	err = msg.Decode(decodedOTKMsg)
	if err != nil {
		return false, err
	}
	if !msg.CheckFields(theirIdentityKey) {
		return false, nil
	}

	same := true
	if msg.IdentityKey != nil {
		same = same && msg.IdentityKey.Equal(s.AliceIdentityKey)
	}
	if theirIdentityKey != nil {
		same = same && theirIdentityKey.Equal(s.AliceIdentityKey)
	}
	same = same && bytes.Equal(msg.BaseKey, s.AliceBaseKey)
	same = same && bytes.Equal(msg.OneTimeKey, s.BobOneTimeKey)
	return same, nil
}

// EncryptMsgType returns the type of the next message that Encrypt will
// return. Returns MsgTypePreKey if the message will be a oneTimeKeyMsg.
// Returns MsgTypeMsg if the message will be a normal message.
func (s *OlmSession) EncryptMsgType() id.OlmMsgType {
	if s.ReceivedMessage {
		return id.OlmMsgTypeMsg
	}
	return id.OlmMsgTypePreKey
}

// Encrypt encrypts a message using the Session. Returns the encrypted message base64 encoded.
func (s *OlmSession) Encrypt(plaintext []byte) (id.OlmMsgType, []byte, error) {
	if len(plaintext) == 0 {
		return 0, nil, fmt.Errorf("encrypt: %w", olm.ErrEmptyInput)
	}
	messageType := s.EncryptMsgType()
	encrypted, err := s.Ratchet.Encrypt(plaintext)
	if err != nil {
		return 0, nil, err
	}
	result := encrypted
	if !s.ReceivedMessage {
		msg := message.PreKeyMessage{}
		msg.Version = protocolVersion
		msg.OneTimeKey = s.BobOneTimeKey
		msg.IdentityKey = s.AliceIdentityKey
		msg.BaseKey = s.AliceBaseKey
		msg.Message = encrypted

		var err error
		messageBody, err := msg.Encode()
		if err != nil {
			return 0, nil, err
		}
		result = messageBody
	}

	return messageType, goolmbase64.Encode(result), nil
}

// Decrypt decrypts a base64 encoded message using the Session.
func (s *OlmSession) Decrypt(crypttext string, msgType id.OlmMsgType) ([]byte, error) {
	if len(crypttext) == 0 {
		return nil, fmt.Errorf("decrypt: %w", olm.ErrEmptyInput)
	}
	decodedCrypttext, err := goolmbase64.Decode([]byte(crypttext))
	if err != nil {
		return nil, err
	}
	msgBody := decodedCrypttext
	if msgType != id.OlmMsgTypeMsg {
		//Pre-Key Message
		msg := message.PreKeyMessage{}
		err := msg.Decode(decodedCrypttext)
		if err != nil {
			return nil, err
		}
		msgBody = msg.Message
	}
	plaintext, err := s.Ratchet.Decrypt(msgBody)
	if err != nil {
		return nil, err
	}
	s.ReceivedMessage = true
	return plaintext, nil
}

// Unpickle decodes the base64 encoded string and decrypts the result with the key.
// The decrypted value is then passed to UnpickleLibOlm.
func (o *OlmSession) Unpickle(pickled, key []byte) error {
	if len(pickled) == 0 {
		return olm.ErrEmptyInput
	}
	decrypted, err := libolmpickle.Unpickle(key, pickled)
	if err != nil {
		return err
	}
	return o.UnpickleLibOlm(decrypted)
}

// UnpickleLibOlm unpickles the unencryted value and populates the [OlmSession]
// accordingly.
func (o *OlmSession) UnpickleLibOlm(buf []byte) error {
	decoder := libolmpickle.NewDecoder(buf)
	pickledVersion, err := decoder.ReadUInt32()

	var includesChainIndex bool
	switch pickledVersion {
	case olmSessionPickleVersionLibOlm:
		includesChainIndex = false
	case uint32(0x80000001):
		includesChainIndex = true
	default:
		return fmt.Errorf("unpickle olmSession: %w (found version %d)", olm.ErrBadVersion, pickledVersion)
	}

	if o.ReceivedMessage, err = decoder.ReadBool(); err != nil {
		return err
	} else if err = o.AliceIdentityKey.UnpickleLibOlm(decoder); err != nil {
		return err
	} else if err = o.AliceBaseKey.UnpickleLibOlm(decoder); err != nil {
		return err
	} else if err = o.BobOneTimeKey.UnpickleLibOlm(decoder); err != nil {
		return err
	}
	return o.Ratchet.UnpickleLibOlm(decoder, includesChainIndex)
}

// Pickle returns a base64 encoded and with key encrypted pickled olmSession
// using PickleLibOlm().
func (s *OlmSession) Pickle(key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, olm.ErrNoKeyProvided
	}
	return libolmpickle.Pickle(key, s.PickleLibOlm())
}

// PickleLibOlm pickles the session and returns the raw bytes.
func (o *OlmSession) PickleLibOlm() []byte {
	encoder := libolmpickle.NewEncoder()
	encoder.WriteUInt32(olmSessionPickleVersionLibOlm)
	encoder.WriteBool(o.ReceivedMessage)
	o.AliceIdentityKey.PickleLibOlm(encoder)
	o.AliceBaseKey.PickleLibOlm(encoder)
	o.BobOneTimeKey.PickleLibOlm(encoder)
	o.Ratchet.PickleLibOlm(encoder)
	return encoder.Bytes()
}

// Describe returns a string describing the current state of the session for debugging.
func (o *OlmSession) Describe() string {
	var builder strings.Builder
	builder.WriteString("sender chain index: ")
	builder.WriteString(fmt.Sprint(o.Ratchet.SenderChains.CKey.Index))
	builder.WriteString(" receiver chain indices:")
	for _, curChain := range o.Ratchet.ReceiverChains {
		builder.WriteString(fmt.Sprintf(" %d", curChain.CKey.Index))
	}
	builder.WriteString(" skipped message keys:")
	for _, curSkip := range o.Ratchet.SkippedMessageKeys {
		builder.WriteString(fmt.Sprintf(" %d", curSkip.MKey.Index))
	}
	return builder.String()
}
