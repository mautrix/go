//go:build goolm

package olm

import (
	"github.com/element-hq/mautrix-go/crypto/goolm/session"
	"github.com/element-hq/mautrix-go/id"
)

// OutboundGroupSession stores an outbound encrypted messaging session for a
// group.
type OutboundGroupSession struct {
	session.MegolmOutboundSession
}

// OutboundGroupSessionFromPickled loads an OutboundGroupSession from a pickled
// base64 string.  Decrypts the OutboundGroupSession using the supplied key.
// Returns error on failure.  If the key doesn't match the one used to encrypt
// the OutboundGroupSession then the error will be "BAD_SESSION_KEY".  If the
// base64 couldn't be decoded then the error will be "INVALID_BASE64".
func OutboundGroupSessionFromPickled(pickled, key []byte) (*OutboundGroupSession, error) {
	if len(pickled) == 0 {
		return nil, EmptyInput
	}
	lenKey := len(key)
	if lenKey == 0 {
		key = []byte(" ")
	}
	megolmSession, err := session.MegolmOutboundSessionFromPickled(pickled, key)
	if err != nil {
		return nil, err
	}
	return &OutboundGroupSession{
		MegolmOutboundSession: *megolmSession,
	}, nil
}

// NewOutboundGroupSession creates a new outbound group session.
func NewOutboundGroupSession() *OutboundGroupSession {
	megolmSession, err := session.NewMegolmOutboundSession()
	if err != nil {
		panic(err)
	}
	return &OutboundGroupSession{
		MegolmOutboundSession: *megolmSession,
	}
}

// newOutboundGroupSession initialises an empty OutboundGroupSession.
func NewBlankOutboundGroupSession() *OutboundGroupSession {
	return &OutboundGroupSession{}
}

// Clear clears the memory used to back this OutboundGroupSession.
func (s *OutboundGroupSession) Clear() error {
	s.MegolmOutboundSession = session.MegolmOutboundSession{}
	return nil
}

// Pickle returns an OutboundGroupSession as a base64 string. Encrypts the
// OutboundGroupSession using the supplied key.
func (s *OutboundGroupSession) Pickle(key []byte) []byte {
	if len(key) == 0 {
		panic(NoKeyProvided)
	}
	pickled, err := s.MegolmOutboundSession.Pickle(key)
	if err != nil {
		panic(err)
	}
	return pickled
}

func (s *OutboundGroupSession) Unpickle(pickled, key []byte) error {
	if len(key) == 0 {
		return NoKeyProvided
	}
	return s.MegolmOutboundSession.Unpickle(pickled, key)
}

// Encrypt encrypts a message using the Session. Returns the encrypted message
// as base64.
func (s *OutboundGroupSession) Encrypt(plaintext []byte) []byte {
	if len(plaintext) == 0 {
		panic(EmptyInput)
	}
	message, err := s.MegolmOutboundSession.Encrypt(plaintext)
	if err != nil {
		panic(err)
	}
	return message
}

// ID returns a base64-encoded identifier for this session.
func (s *OutboundGroupSession) ID() id.SessionID {
	return s.MegolmOutboundSession.SessionID()
}

// MessageIndex returns the message index for this session.  Each message is
// sent with an increasing index; this returns the index for the next message.
func (s *OutboundGroupSession) MessageIndex() uint {
	return uint(s.MegolmOutboundSession.Ratchet.Counter)
}

// Key returns the base64-encoded current ratchet key for this session.
func (s *OutboundGroupSession) Key() string {
	message, err := s.MegolmOutboundSession.SessionSharingMessage()
	if err != nil {
		panic(err)
	}
	return string(message)
}
