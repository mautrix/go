//go:build goolm

package olm

import (
	"encoding/base64"

	"codeberg.org/DerLukas/goolm/session"
	"maunium.net/go/mautrix/id"
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
		return nil, ErrEmptyInput
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
		panic(ErrNoKeyProvided)
	}
	pickled, err := s.MegolmOutboundSession.Pickle(key)
	if err != nil {
		panic(err)
	}
	return pickled
}

func (s *OutboundGroupSession) Unpickle(pickled, key []byte) error {
	if len(key) == 0 {
		return ErrNoKeyProvided
	}
	return s.MegolmOutboundSession.Unpickle(pickled, key)
}

func (s *OutboundGroupSession) GobEncode() ([]byte, error) {
	pickled, err := s.MegolmOutboundSession.Pickle(pickleKey)
	if err != nil {
		return nil, err
	}
	length := base64.RawStdEncoding.DecodedLen(len(pickled))
	rawPickled := make([]byte, length)
	_, err = base64.RawStdEncoding.Decode(rawPickled, pickled)
	return rawPickled, err
}

func (s *OutboundGroupSession) GobDecode(rawPickled []byte) error {
	if s == nil {
		*s = *NewBlankOutboundGroupSession()
	}
	length := base64.RawStdEncoding.EncodedLen(len(rawPickled))
	pickled := make([]byte, length)
	base64.RawStdEncoding.Encode(pickled, rawPickled)
	return s.Unpickle(pickled, pickleKey)
}

func (s *OutboundGroupSession) MarshalJSON() ([]byte, error) {
	pickled, err := s.MegolmOutboundSession.Pickle(pickleKey)
	if err != nil {
		return nil, err
	}
	quotes := make([]byte, len(pickled)+2)
	quotes[0] = '"'
	quotes[len(quotes)-1] = '"'
	copy(quotes[1:len(quotes)-1], pickled)
	return quotes, nil
}

func (s *OutboundGroupSession) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || data[0] != '"' || data[len(data)-1] != '"' {
		return ErrInputNotJSONString
	}
	if s == nil {
		*s = *NewBlankOutboundGroupSession()
	}
	return s.Unpickle(data[1:len(data)-1], pickleKey)
}

// Encrypt encrypts a message using the Session. Returns the encrypted message
// as base64.
func (s *OutboundGroupSession) Encrypt(plaintext []byte) []byte {
	if len(plaintext) == 0 {
		panic(ErrEmptyInput)
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
