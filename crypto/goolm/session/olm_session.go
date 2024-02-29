package session

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/element-hq/mautrix-go/crypto/goolm"
	"github.com/element-hq/mautrix-go/crypto/goolm/cipher"
	"github.com/element-hq/mautrix-go/crypto/goolm/crypto"
	"github.com/element-hq/mautrix-go/crypto/goolm/libolmpickle"
	"github.com/element-hq/mautrix-go/crypto/goolm/message"
	"github.com/element-hq/mautrix-go/crypto/goolm/olm"
	"github.com/element-hq/mautrix-go/crypto/goolm/utilities"
	"github.com/element-hq/mautrix-go/id"
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
	Ratchet          olm.Ratchet                `json:"ratchet"`
}

// SearchOTKFunc is used to retrieve a crypto.OneTimeKey from a public key.
type SearchOTKFunc = func(crypto.Curve25519PublicKey) *crypto.OneTimeKey

// OlmSessionFromJSONPickled loads an OlmSession from a pickled base64 string. Decrypts
// the Session using the supplied key.
func OlmSessionFromJSONPickled(pickled, key []byte) (*OlmSession, error) {
	if len(pickled) == 0 {
		return nil, fmt.Errorf("sessionFromPickled: %w", goolm.ErrEmptyInput)
	}
	a := &OlmSession{}
	err := a.UnpickleAsJSON(pickled, key)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// OlmSessionFromPickled loads the OlmSession details from a pickled base64 string. The input is decrypted with the supplied key.
func OlmSessionFromPickled(pickled, key []byte) (*OlmSession, error) {
	if len(pickled) == 0 {
		return nil, fmt.Errorf("sessionFromPickled: %w", goolm.ErrEmptyInput)
	}
	a := &OlmSession{}
	err := a.Unpickle(pickled, key)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// NewOlmSession creates a new Session.
func NewOlmSession() *OlmSession {
	s := &OlmSession{}
	s.Ratchet = *olm.New()
	return s
}

// NewOutboundOlmSession creates a new outbound session for sending the first message to a
// given curve25519 identityKey and oneTimeKey.
func NewOutboundOlmSession(identityKeyAlice crypto.Curve25519KeyPair, identityKeyBob crypto.Curve25519PublicKey, oneTimeKeyBob crypto.Curve25519PublicKey) (*OlmSession, error) {
	s := NewOlmSession()
	//generate E_A
	baseKey, err := crypto.Curve25519GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	//generate T_0
	ratchetKey, err := crypto.Curve25519GenerateKey(nil)
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
	decodedOTKMsg, err := goolm.Base64Decode(receivedOTKMsg)
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
		return nil, fmt.Errorf("OneTimeKeyMessage check fields: %w", goolm.ErrBadMessageFormat)
	}

	//Either the identityKeyAlice is set and/or the oneTimeMsg.IdentityKey is set, which is checked
	// by oneTimeMsg.CheckFields
	if identityKeyAlice != nil && len(oneTimeMsg.IdentityKey) != 0 {
		//if both are set, compare them
		if !identityKeyAlice.Equal(oneTimeMsg.IdentityKey) {
			return nil, fmt.Errorf("OneTimeKeyMessage identity keys: %w", goolm.ErrBadMessageKeyID)
		}
	}
	if identityKeyAlice == nil {
		//for downstream use set
		identityKeyAlice = &oneTimeMsg.IdentityKey
	}

	oneTimeKeyBob := searchBobOTK(oneTimeMsg.OneTimeKey)
	if oneTimeKeyBob == nil {
		return nil, fmt.Errorf("ourOneTimeKey: %w", goolm.ErrBadMessageKeyID)
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
		return nil, fmt.Errorf("Message missing ratchet key: %w", goolm.ErrBadMessageFormat)
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
	return utilities.PickleAsJSON(a, olmSessionPickleVersionJSON, key)
}

// UnpickleAsJSON updates an Session by a base64 encrypted string with the key. The unencrypted representation has to be in JSON format.
func (a *OlmSession) UnpickleAsJSON(pickled, key []byte) error {
	return utilities.UnpickleAsJSON(a, pickled, key, olmSessionPickleVersionJSON)
}

// ID returns an identifier for this Session.  Will be the same for both ends of the conversation.
// Generated by hashing the public keys used to create the session.
func (s OlmSession) ID() id.SessionID {
	message := make([]byte, 3*crypto.Curve25519KeyLength)
	copy(message, s.AliceIdentityKey)
	copy(message[crypto.Curve25519KeyLength:], s.AliceBaseKey)
	copy(message[2*crypto.Curve25519KeyLength:], s.BobOneTimeKey)
	hash := crypto.SHA256(message)
	res := id.SessionID(goolm.Base64Encode(hash))
	return res
}

// HasReceivedMessage returns true if this session has received any message.
func (s OlmSession) HasReceivedMessage() bool {
	return s.ReceivedMessage
}

// MatchesInboundSessionFrom checks if the oneTimeKeyMsg message is set for this inbound
// Session.  This can happen if multiple messages are sent to this Account
// before this Account sends a message in reply.  Returns true if the session
// matches.  Returns false if the session does not match.
func (s OlmSession) MatchesInboundSessionFrom(theirIdentityKeyEncoded *id.Curve25519, receivedOTKMsg []byte) (bool, error) {
	if len(receivedOTKMsg) == 0 {
		return false, fmt.Errorf("inbound match: %w", goolm.ErrEmptyInput)
	}
	decodedOTKMsg, err := goolm.Base64Decode(receivedOTKMsg)
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
func (s OlmSession) EncryptMsgType() id.OlmMsgType {
	if s.ReceivedMessage {
		return id.OlmMsgTypeMsg
	}
	return id.OlmMsgTypePreKey
}

// Encrypt encrypts a message using the Session. Returns the encrypted message base64 encoded.  If reader is nil, crypto/rand is used for key generations.
func (s *OlmSession) Encrypt(plaintext []byte, reader io.Reader) (id.OlmMsgType, []byte, error) {
	if len(plaintext) == 0 {
		return 0, nil, fmt.Errorf("encrypt: %w", goolm.ErrEmptyInput)
	}
	messageType := s.EncryptMsgType()
	encrypted, err := s.Ratchet.Encrypt(plaintext, reader)
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

	return messageType, goolm.Base64Encode(result), nil
}

// Decrypt decrypts a base64 encoded message using the Session.
func (s *OlmSession) Decrypt(crypttext []byte, msgType id.OlmMsgType) ([]byte, error) {
	if len(crypttext) == 0 {
		return nil, fmt.Errorf("decrypt: %w", goolm.ErrEmptyInput)
	}
	decodedCrypttext, err := goolm.Base64Decode(crypttext)
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
	decrypted, err := cipher.Unpickle(key, pickled)
	if err != nil {
		return err
	}
	_, err = o.UnpickleLibOlm(decrypted)
	return err
}

// UnpickleLibOlm decodes the unencryted value and populates the Session accordingly. It returns the number of bytes read.
func (o *OlmSession) UnpickleLibOlm(value []byte) (int, error) {
	//First 4 bytes are the accountPickleVersion
	pickledVersion, curPos, err := libolmpickle.UnpickleUInt32(value)
	if err != nil {
		return 0, err
	}
	includesChainIndex := true
	switch pickledVersion {
	case olmSessionPickleVersionLibOlm:
		includesChainIndex = false
	case uint32(0x80000001):
		includesChainIndex = true
	default:
		return 0, fmt.Errorf("unpickle olmSession: %w", goolm.ErrBadVersion)
	}
	var readBytes int
	o.ReceivedMessage, readBytes, err = libolmpickle.UnpickleBool(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	readBytes, err = o.AliceIdentityKey.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	readBytes, err = o.AliceBaseKey.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	readBytes, err = o.BobOneTimeKey.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	readBytes, err = o.Ratchet.UnpickleLibOlm(value[curPos:], includesChainIndex)
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	return curPos, nil
}

// Pickle returns a base64 encoded and with key encrypted pickled olmSession using PickleLibOlm().
func (o OlmSession) Pickle(key []byte) ([]byte, error) {
	pickeledBytes := make([]byte, o.PickleLen())
	written, err := o.PickleLibOlm(pickeledBytes)
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

// PickleLibOlm encodes the session into target. target has to have a size of at least PickleLen() and is written to from index 0.
// It returns the number of bytes written.
func (o OlmSession) PickleLibOlm(target []byte) (int, error) {
	if len(target) < o.PickleLen() {
		return 0, fmt.Errorf("pickle MegolmOutboundSession: %w", goolm.ErrValueTooShort)
	}
	written := libolmpickle.PickleUInt32(olmSessionPickleVersionLibOlm, target)
	written += libolmpickle.PickleBool(o.ReceivedMessage, target[written:])
	writtenRatchet, err := o.AliceIdentityKey.PickleLibOlm(target[written:])
	if err != nil {
		return 0, fmt.Errorf("pickle MegolmOutboundSession: %w", err)
	}
	written += writtenRatchet
	writtenRatchet, err = o.AliceBaseKey.PickleLibOlm(target[written:])
	if err != nil {
		return 0, fmt.Errorf("pickle MegolmOutboundSession: %w", err)
	}
	written += writtenRatchet
	writtenRatchet, err = o.BobOneTimeKey.PickleLibOlm(target[written:])
	if err != nil {
		return 0, fmt.Errorf("pickle MegolmOutboundSession: %w", err)
	}
	written += writtenRatchet
	writtenRatchet, err = o.Ratchet.PickleLibOlm(target[written:])
	if err != nil {
		return 0, fmt.Errorf("pickle MegolmOutboundSession: %w", err)
	}
	written += writtenRatchet
	return written, nil
}

// PickleLen returns the actual number of bytes the pickled session will have.
func (o OlmSession) PickleLen() int {
	length := libolmpickle.PickleUInt32Len(olmSessionPickleVersionLibOlm)
	length += libolmpickle.PickleBoolLen(o.ReceivedMessage)
	length += o.AliceIdentityKey.PickleLen()
	length += o.AliceBaseKey.PickleLen()
	length += o.BobOneTimeKey.PickleLen()
	length += o.Ratchet.PickleLen()
	return length
}

// PickleLenMin returns the minimum number of bytes the pickled session must have.
func (o OlmSession) PickleLenMin() int {
	length := libolmpickle.PickleUInt32Len(olmSessionPickleVersionLibOlm)
	length += libolmpickle.PickleBoolLen(o.ReceivedMessage)
	length += o.AliceIdentityKey.PickleLen()
	length += o.AliceBaseKey.PickleLen()
	length += o.BobOneTimeKey.PickleLen()
	length += o.Ratchet.PickleLenMin()
	return length
}

// Describe returns a string describing the current state of the session for debugging.
func (o OlmSession) Describe() string {
	var res string
	if o.Ratchet.SenderChains.IsSet {
		res += fmt.Sprintf("sender chain index: %d ", o.Ratchet.SenderChains.CKey.Index)
	} else {
		res += "sender chain index: "
	}
	res += "receiver chain indicies:"
	for _, curChain := range o.Ratchet.ReceiverChains {
		res += fmt.Sprintf(" %d", curChain.CKey.Index)
	}
	res += " skipped message keys:"
	for _, curSkip := range o.Ratchet.SkippedMessageKeys {
		res += fmt.Sprintf(" %d", curSkip.MKey.Index)
	}
	return res
}
