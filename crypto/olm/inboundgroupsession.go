//go:build !goolm

package olm

// #cgo LDFLAGS: -lolm -lstdc++
// #include <olm/olm.h>
import "C"

import (
	"encoding/base64"
	"unsafe"

	"github.com/element-hq/mautrix-go/id"
)

// InboundGroupSession stores an inbound encrypted messaging session for a
// group.
type InboundGroupSession struct {
	int *C.OlmInboundGroupSession
	mem []byte
}

// InboundGroupSessionFromPickled loads an InboundGroupSession from a pickled
// base64 string.  Decrypts the InboundGroupSession using the supplied key.
// Returns error on failure.  If the key doesn't match the one used to encrypt
// the InboundGroupSession then the error will be "BAD_SESSION_KEY".  If the
// base64 couldn't be decoded then the error will be "INVALID_BASE64".
func InboundGroupSessionFromPickled(pickled, key []byte) (*InboundGroupSession, error) {
	if len(pickled) == 0 {
		return nil, EmptyInput
	}
	lenKey := len(key)
	if lenKey == 0 {
		key = []byte(" ")
	}
	s := NewBlankInboundGroupSession()
	return s, s.Unpickle(pickled, key)
}

// NewInboundGroupSession creates a new inbound group session from a key
// exported from OutboundGroupSession.Key().  Returns error on failure.
// If the sessionKey is not valid base64 the error will be
// "OLM_INVALID_BASE64".  If the session_key is invalid the error will be
// "OLM_BAD_SESSION_KEY".
func NewInboundGroupSession(sessionKey []byte) (*InboundGroupSession, error) {
	if len(sessionKey) == 0 {
		return nil, EmptyInput
	}
	s := NewBlankInboundGroupSession()
	r := C.olm_init_inbound_group_session(
		(*C.OlmInboundGroupSession)(s.int),
		(*C.uint8_t)(&sessionKey[0]),
		C.size_t(len(sessionKey)))
	if r == errorVal() {
		return nil, s.lastError()
	}
	return s, nil
}

// InboundGroupSessionImport imports an inbound group session from a previous
// export.  Returns error on failure.  If the sessionKey is not valid base64
// the error will be "OLM_INVALID_BASE64".  If the session_key is invalid the
// error will be "OLM_BAD_SESSION_KEY".
func InboundGroupSessionImport(sessionKey []byte) (*InboundGroupSession, error) {
	if len(sessionKey) == 0 {
		return nil, EmptyInput
	}
	s := NewBlankInboundGroupSession()
	r := C.olm_import_inbound_group_session(
		(*C.OlmInboundGroupSession)(s.int),
		(*C.uint8_t)(&sessionKey[0]),
		C.size_t(len(sessionKey)))
	if r == errorVal() {
		return nil, s.lastError()
	}
	return s, nil
}

// inboundGroupSessionSize is the size of an inbound group session object in
// bytes.
func inboundGroupSessionSize() uint {
	return uint(C.olm_inbound_group_session_size())
}

// newInboundGroupSession initialises an empty InboundGroupSession.
func NewBlankInboundGroupSession() *InboundGroupSession {
	memory := make([]byte, inboundGroupSessionSize())
	return &InboundGroupSession{
		int: C.olm_inbound_group_session(unsafe.Pointer(&memory[0])),
		mem: memory,
	}
}

// lastError returns an error describing the most recent error to happen to an
// inbound group session.
func (s *InboundGroupSession) lastError() error {
	return convertError(C.GoString(C.olm_inbound_group_session_last_error((*C.OlmInboundGroupSession)(s.int))))
}

// Clear clears the memory used to back this InboundGroupSession.
func (s *InboundGroupSession) Clear() error {
	r := C.olm_clear_inbound_group_session((*C.OlmInboundGroupSession)(s.int))
	if r == errorVal() {
		return s.lastError()
	}
	return nil
}

// pickleLen returns the number of bytes needed to store an inbound group
// session.
func (s *InboundGroupSession) pickleLen() uint {
	return uint(C.olm_pickle_inbound_group_session_length((*C.OlmInboundGroupSession)(s.int)))
}

// Pickle returns an InboundGroupSession as a base64 string.  Encrypts the
// InboundGroupSession using the supplied key.
func (s *InboundGroupSession) Pickle(key []byte) []byte {
	if len(key) == 0 {
		panic(NoKeyProvided)
	}
	pickled := make([]byte, s.pickleLen())
	r := C.olm_pickle_inbound_group_session(
		(*C.OlmInboundGroupSession)(s.int),
		unsafe.Pointer(&key[0]),
		C.size_t(len(key)),
		unsafe.Pointer(&pickled[0]),
		C.size_t(len(pickled)))
	if r == errorVal() {
		panic(s.lastError())
	}
	return pickled[:r]
}

func (s *InboundGroupSession) Unpickle(pickled, key []byte) error {
	if len(key) == 0 {
		return NoKeyProvided
	} else if len(pickled) == 0 {
		return EmptyInput
	}
	r := C.olm_unpickle_inbound_group_session(
		(*C.OlmInboundGroupSession)(s.int),
		unsafe.Pointer(&key[0]),
		C.size_t(len(key)),
		unsafe.Pointer(&pickled[0]),
		C.size_t(len(pickled)))
	if r == errorVal() {
		return s.lastError()
	}
	return nil
}

// Deprecated
func (s *InboundGroupSession) GobEncode() ([]byte, error) {
	pickled := s.Pickle(pickleKey)
	length := base64.RawStdEncoding.DecodedLen(len(pickled))
	rawPickled := make([]byte, length)
	_, err := base64.RawStdEncoding.Decode(rawPickled, pickled)
	return rawPickled, err
}

// Deprecated
func (s *InboundGroupSession) GobDecode(rawPickled []byte) error {
	if s == nil || s.int == nil {
		*s = *NewBlankInboundGroupSession()
	}
	length := base64.RawStdEncoding.EncodedLen(len(rawPickled))
	pickled := make([]byte, length)
	base64.RawStdEncoding.Encode(pickled, rawPickled)
	return s.Unpickle(pickled, pickleKey)
}

// Deprecated
func (s *InboundGroupSession) MarshalJSON() ([]byte, error) {
	pickled := s.Pickle(pickleKey)
	quotes := make([]byte, len(pickled)+2)
	quotes[0] = '"'
	quotes[len(quotes)-1] = '"'
	copy(quotes[1:len(quotes)-1], pickled)
	return quotes, nil
}

// Deprecated
func (s *InboundGroupSession) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || data[0] != '"' || data[len(data)-1] != '"' {
		return InputNotJSONString
	}
	if s == nil || s.int == nil {
		*s = *NewBlankInboundGroupSession()
	}
	return s.Unpickle(data[1:len(data)-1], pickleKey)
}

func clone(original []byte) []byte {
	clone := make([]byte, len(original))
	copy(clone, original)
	return clone
}

// decryptMaxPlaintextLen returns the maximum number of bytes of plain-text a
// given message could decode to.  The actual size could be different due to
// padding.  Returns error on failure.  If the message base64 couldn't be
// decoded then the error will be "INVALID_BASE64".  If the message is for an
// unsupported version of the protocol then the error will be
// "BAD_MESSAGE_VERSION".  If the message couldn't be decoded then the error
// will be "BAD_MESSAGE_FORMAT".
func (s *InboundGroupSession) decryptMaxPlaintextLen(message []byte) (uint, error) {
	if len(message) == 0 {
		return 0, EmptyInput
	}
	// olm_group_decrypt_max_plaintext_length destroys the input, so we have to clone it
	message = clone(message)
	r := C.olm_group_decrypt_max_plaintext_length(
		(*C.OlmInboundGroupSession)(s.int),
		(*C.uint8_t)(&message[0]),
		C.size_t(len(message)))
	if r == errorVal() {
		return 0, s.lastError()
	}
	return uint(r), nil
}

// Decrypt decrypts a message using the InboundGroupSession.  Returns the the
// plain-text and message index on success.  Returns error on failure.  If the
// base64 couldn't be decoded then the error will be "INVALID_BASE64".  If the
// message is for an unsupported version of the protocol then the error will be
// "BAD_MESSAGE_VERSION".  If the message couldn't be decoded then the error
// will be BAD_MESSAGE_FORMAT".  If the MAC on the message was invalid then the
// error will be "BAD_MESSAGE_MAC".  If we do not have a session key
// corresponding to the message's index (ie, it was sent before the session key
// was shared with us) the error will be "OLM_UNKNOWN_MESSAGE_INDEX".
func (s *InboundGroupSession) Decrypt(message []byte) ([]byte, uint, error) {
	if len(message) == 0 {
		return nil, 0, EmptyInput
	}
	decryptMaxPlaintextLen, err := s.decryptMaxPlaintextLen(message)
	if err != nil {
		return nil, 0, err
	}
	messageCopy := make([]byte, len(message))
	copy(messageCopy, message)
	plaintext := make([]byte, decryptMaxPlaintextLen)
	var messageIndex uint32
	r := C.olm_group_decrypt(
		(*C.OlmInboundGroupSession)(s.int),
		(*C.uint8_t)(&messageCopy[0]),
		C.size_t(len(messageCopy)),
		(*C.uint8_t)(&plaintext[0]),
		C.size_t(len(plaintext)),
		(*C.uint32_t)(&messageIndex))
	if r == errorVal() {
		return nil, 0, s.lastError()
	}
	return plaintext[:r], uint(messageIndex), nil
}

// sessionIdLen returns the number of bytes needed to store a session ID.
func (s *InboundGroupSession) sessionIdLen() uint {
	return uint(C.olm_inbound_group_session_id_length((*C.OlmInboundGroupSession)(s.int)))
}

// ID returns a base64-encoded identifier for this session.
func (s *InboundGroupSession) ID() id.SessionID {
	sessionID := make([]byte, s.sessionIdLen())
	r := C.olm_inbound_group_session_id(
		(*C.OlmInboundGroupSession)(s.int),
		(*C.uint8_t)(&sessionID[0]),
		C.size_t(len(sessionID)))
	if r == errorVal() {
		panic(s.lastError())
	}
	return id.SessionID(sessionID[:r])
}

// FirstKnownIndex returns the first message index we know how to decrypt.
func (s *InboundGroupSession) FirstKnownIndex() uint32 {
	return uint32(C.olm_inbound_group_session_first_known_index((*C.OlmInboundGroupSession)(s.int)))
}

// IsVerified check if the session has been verified as a valid session.  (A
// session is verified either because the original session share was signed, or
// because we have subsequently successfully decrypted a message.)
func (s *InboundGroupSession) IsVerified() uint {
	return uint(C.olm_inbound_group_session_is_verified((*C.OlmInboundGroupSession)(s.int)))
}

// exportLen returns the number of bytes needed to export an inbound group
// session.
func (s *InboundGroupSession) exportLen() uint {
	return uint(C.olm_export_inbound_group_session_length((*C.OlmInboundGroupSession)(s.int)))
}

// Export returns the base64-encoded ratchet key for this session, at the given
// index, in a format which can be used by
// InboundGroupSession.InboundGroupSessionImport().  Encrypts the
// InboundGroupSession using the supplied key.  Returns error on failure.
// if we do not have a session key corresponding to the given index (ie, it was
// sent before the session key was shared with us) the error will be
// "OLM_UNKNOWN_MESSAGE_INDEX".
func (s *InboundGroupSession) Export(messageIndex uint32) ([]byte, error) {
	key := make([]byte, s.exportLen())
	r := C.olm_export_inbound_group_session(
		(*C.OlmInboundGroupSession)(s.int),
		(*C.uint8_t)(&key[0]),
		C.size_t(len(key)),
		C.uint32_t(messageIndex))
	if r == errorVal() {
		return nil, s.lastError()
	}
	return key[:r], nil
}
