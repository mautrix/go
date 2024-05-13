//go:build goolm

package olm

import (
	"maunium.net/go/mautrix/crypto/goolm/session"
)

// OutboundGroupSessionFromPickled loads an OutboundGroupSession from a pickled
// base64 string.  Decrypts the OutboundGroupSession using the supplied key.
// Returns error on failure.  If the key doesn't match the one used to encrypt
// the OutboundGroupSession then the error will be "BAD_SESSION_KEY".  If the
// base64 couldn't be decoded then the error will be "INVALID_BASE64".
func OutboundGroupSessionFromPickled(pickled, key []byte) (OutboundGroupSession, error) {
	if len(pickled) == 0 {
		return nil, EmptyInput
	}
	lenKey := len(key)
	if lenKey == 0 {
		key = []byte(" ")
	}
	return session.MegolmOutboundSessionFromPickled(pickled, key)
}

// NewOutboundGroupSession creates a new outbound group session.
func NewOutboundGroupSession() OutboundGroupSession {
	session, err := session.NewMegolmOutboundSession()
	if err != nil {
		panic(err)
	}
	return session
}

// NewBlankOutboundGroupSession initialises an empty OutboundGroupSession.
func NewBlankOutboundGroupSession() OutboundGroupSession {
	return &session.MegolmOutboundSession{}
}
