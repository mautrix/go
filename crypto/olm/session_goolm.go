//go:build goolm

package olm

import (
	"github.com/element-hq/mautrix-go/crypto/goolm/session"
	"github.com/element-hq/mautrix-go/id"
)

// Session stores an end to end encrypted messaging session.
type Session struct {
	session.OlmSession
}

// SessionFromPickled loads a Session from a pickled base64 string.  Decrypts
// the Session using the supplied key.  Returns error on failure.
func SessionFromPickled(pickled, key []byte) (*Session, error) {
	if len(pickled) == 0 {
		return nil, EmptyInput
	}
	s := NewBlankSession()
	return s, s.Unpickle(pickled, key)
}

func NewBlankSession() *Session {
	return &Session{}
}

// Clear clears the memory used to back this Session.
func (s *Session) Clear() error {
	s.OlmSession = session.OlmSession{}
	return nil
}

// Pickle returns a Session as a base64 string.  Encrypts the Session using the
// supplied key.
func (s *Session) Pickle(key []byte) []byte {
	if len(key) == 0 {
		panic(NoKeyProvided)
	}
	pickled, err := s.OlmSession.Pickle(key)
	if err != nil {
		panic(err)
	}
	return pickled
}

func (s *Session) Unpickle(pickled, key []byte) error {
	if len(key) == 0 {
		return NoKeyProvided
	} else if len(pickled) == 0 {
		return EmptyInput
	}
	sOlm, err := session.OlmSessionFromPickled(pickled, key)
	if err != nil {
		return err
	}
	s.OlmSession = *sOlm
	return nil
}

// MatchesInboundSession checks if the PRE_KEY message is for this in-bound
// Session. This can happen if multiple messages are sent to this Account
// before this Account sends a message in reply. Returns true if the session
// matches. Returns false if the session does not match. Returns error on
// failure.
func (s *Session) MatchesInboundSession(oneTimeKeyMsg string) (bool, error) {
	return s.MatchesInboundSessionFrom("", oneTimeKeyMsg)
}

// MatchesInboundSessionFrom checks if the PRE_KEY message is for this in-bound
// Session. This can happen if multiple messages are sent to this Account
// before this Account sends a message in reply. Returns true if the session
// matches. Returns false if the session does not match. Returns error on
// failure.
func (s *Session) MatchesInboundSessionFrom(theirIdentityKey, oneTimeKeyMsg string) (bool, error) {
	if theirIdentityKey != "" {
		theirKey := id.Curve25519(theirIdentityKey)
		return s.OlmSession.MatchesInboundSessionFrom(&theirKey, []byte(oneTimeKeyMsg))
	}
	return s.OlmSession.MatchesInboundSessionFrom(nil, []byte(oneTimeKeyMsg))

}

// Encrypt encrypts a message using the Session.  Returns the encrypted message
// as base64.
func (s *Session) Encrypt(plaintext []byte) (id.OlmMsgType, []byte) {
	if len(plaintext) == 0 {
		panic(EmptyInput)
	}
	messageType, message, err := s.OlmSession.Encrypt(plaintext, nil)
	if err != nil {
		panic(err)
	}
	return messageType, message
}

// Decrypt decrypts a message using the Session. Returns the the plain-text on
// success.  Returns error on failure.
func (s *Session) Decrypt(message string, msgType id.OlmMsgType) ([]byte, error) {
	if len(message) == 0 {
		return nil, EmptyInput
	}
	return s.OlmSession.Decrypt([]byte(message), msgType)
}

// Describe generates a string describing the internal state of an olm session for debugging and logging purposes.
func (s *Session) Describe() string {
	return s.OlmSession.Describe()
}
