//go:build goolm

package olm

import (
	"github.com/element-hq/mautrix-go/crypto/goolm/session"
	"github.com/element-hq/mautrix-go/id"
)

// InboundGroupSession stores an inbound encrypted messaging session for a
// group.
type InboundGroupSession struct {
	session.MegolmInboundSession
}

// InboundGroupSessionFromPickled loads an InboundGroupSession from a pickled
// base64 string. Decrypts the InboundGroupSession using the supplied key.
// Returns error on failure.
func InboundGroupSessionFromPickled(pickled, key []byte) (*InboundGroupSession, error) {
	if len(pickled) == 0 {
		return nil, EmptyInput
	}
	lenKey := len(key)
	if lenKey == 0 {
		key = []byte(" ")
	}
	megolmSession, err := session.MegolmInboundSessionFromPickled(pickled, key)
	if err != nil {
		return nil, err
	}
	return &InboundGroupSession{
		MegolmInboundSession: *megolmSession,
	}, nil
}

// NewInboundGroupSession creates a new inbound group session from a key
// exported from OutboundGroupSession.Key(). Returns error on failure.
func NewInboundGroupSession(sessionKey []byte) (*InboundGroupSession, error) {
	if len(sessionKey) == 0 {
		return nil, EmptyInput
	}
	megolmSession, err := session.NewMegolmInboundSession(sessionKey)
	if err != nil {
		return nil, err
	}
	return &InboundGroupSession{
		MegolmInboundSession: *megolmSession,
	}, nil
}

// InboundGroupSessionImport imports an inbound group session from a previous
// export. Returns error on failure.
func InboundGroupSessionImport(sessionKey []byte) (*InboundGroupSession, error) {
	if len(sessionKey) == 0 {
		return nil, EmptyInput
	}
	megolmSession, err := session.NewMegolmInboundSessionFromExport(sessionKey)
	if err != nil {
		return nil, err
	}
	return &InboundGroupSession{
		MegolmInboundSession: *megolmSession,
	}, nil
}

func NewBlankInboundGroupSession() *InboundGroupSession {
	return &InboundGroupSession{}
}

// Clear clears the memory used to back this InboundGroupSession.
func (s *InboundGroupSession) Clear() error {
	s.MegolmInboundSession = session.MegolmInboundSession{}
	return nil
}

// Pickle returns an InboundGroupSession as a base64 string. Encrypts the
// InboundGroupSession using the supplied key.
func (s *InboundGroupSession) Pickle(key []byte) []byte {
	if len(key) == 0 {
		panic(NoKeyProvided)
	}
	pickled, err := s.MegolmInboundSession.Pickle(key)
	if err != nil {
		panic(err)
	}
	return pickled
}

func (s *InboundGroupSession) Unpickle(pickled, key []byte) error {
	if len(key) == 0 {
		return NoKeyProvided
	} else if len(pickled) == 0 {
		return EmptyInput
	}
	sOlm, err := session.MegolmInboundSessionFromPickled(pickled, key)
	if err != nil {
		return err
	}
	s.MegolmInboundSession = *sOlm
	return nil
}

// Decrypt decrypts a message using the InboundGroupSession. Returns the the
// plain-text and message index on success. Returns error on failure.
func (s *InboundGroupSession) Decrypt(message []byte) ([]byte, uint, error) {
	if len(message) == 0 {
		return nil, 0, EmptyInput
	}
	plaintext, messageIndex, err := s.MegolmInboundSession.Decrypt(message)
	if err != nil {
		return nil, 0, err
	}
	return plaintext, uint(messageIndex), nil
}

// ID returns a base64-encoded identifier for this session.
func (s *InboundGroupSession) ID() id.SessionID {
	return s.MegolmInboundSession.SessionID()
}

// FirstKnownIndex returns the first message index we know how to decrypt.
func (s *InboundGroupSession) FirstKnownIndex() uint32 {
	return s.MegolmInboundSession.InitialRatchet.Counter
}

// IsVerified check if the session has been verified as a valid session.  (A
// session is verified either because the original session share was signed, or
// because we have subsequently successfully decrypted a message.)
func (s *InboundGroupSession) IsVerified() uint {
	if s.MegolmInboundSession.SigningKeyVerified {
		return 1
	}
	return 0
}

// Export returns the base64-encoded ratchet key for this session, at the given
// index, in a format which can be used by
// InboundGroupSession.InboundGroupSessionImport().  Encrypts the
// InboundGroupSession using the supplied key.  Returns error on failure.
// if we do not have a session key corresponding to the given index (ie, it was
// sent before the session key was shared with us) the error will be
// returned.
func (s *InboundGroupSession) Export(messageIndex uint32) ([]byte, error) {
	res, err := s.MegolmInboundSession.SessionExportMessage(messageIndex)
	if err != nil {
		return nil, err
	}
	return res, nil
}
