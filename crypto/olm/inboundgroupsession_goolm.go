//go:build goolm

package olm

import (
	"maunium.net/go/mautrix/crypto/goolm/session"
)

// InboundGroupSessionFromPickled loads an InboundGroupSession from a pickled
// base64 string. Decrypts the InboundGroupSession using the supplied key.
// Returns error on failure.
func InboundGroupSessionFromPickled(pickled, key []byte) (InboundGroupSession, error) {
	if len(pickled) == 0 {
		return nil, EmptyInput
	}
	if len(key) == 0 {
		key = []byte(" ")
	}
	return session.MegolmInboundSessionFromPickled(pickled, key)
}

// NewInboundGroupSession creates a new inbound group session from a key
// exported from OutboundGroupSession.Key(). Returns error on failure.
func NewInboundGroupSession(sessionKey []byte) (InboundGroupSession, error) {
	if len(sessionKey) == 0 {
		return nil, EmptyInput
	}
	return session.NewMegolmInboundSession(sessionKey)
}

// InboundGroupSessionImport imports an inbound group session from a previous
// export. Returns error on failure.
func InboundGroupSessionImport(sessionKey []byte) (InboundGroupSession, error) {
	if len(sessionKey) == 0 {
		return nil, EmptyInput
	}
	return session.NewMegolmInboundSessionFromExport(sessionKey)
}

func NewBlankInboundGroupSession() InboundGroupSession {
	return &session.MegolmInboundSession{}
}
