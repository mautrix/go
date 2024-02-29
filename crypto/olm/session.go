//go:build !goolm

package olm

// #cgo LDFLAGS: -lolm -lstdc++
// #include <olm/olm.h>
// #include <stdlib.h>
// #include <stdio.h>
// void olm_session_describe(OlmSession * session, char *buf, size_t buflen) __attribute__((weak));
// void meowlm_session_describe(OlmSession * session, char *buf, size_t buflen) {
//   if (olm_session_describe) {
//     olm_session_describe(session, buf, buflen);
//   } else {
//     sprintf(buf, "olm_session_describe not supported");
//   }
// }
import "C"

import (
	"crypto/rand"
	"encoding/base64"
	"unsafe"

	"github.com/element-hq/mautrix-go/id"
)

// Session stores an end to end encrypted messaging session.
type Session struct {
	int *C.OlmSession
	mem []byte
}

// sessionSize is the size of a session object in bytes.
func sessionSize() uint {
	return uint(C.olm_session_size())
}

// SessionFromPickled loads a Session from a pickled base64 string.  Decrypts
// the Session using the supplied key.  Returns error on failure.  If the key
// doesn't match the one used to encrypt the Session then the error will be
// "BAD_SESSION_KEY".  If the base64 couldn't be decoded then the error will be
// "INVALID_BASE64".
func SessionFromPickled(pickled, key []byte) (*Session, error) {
	if len(pickled) == 0 {
		return nil, EmptyInput
	}
	s := NewBlankSession()
	return s, s.Unpickle(pickled, key)
}

func NewBlankSession() *Session {
	memory := make([]byte, sessionSize())
	return &Session{
		int: C.olm_session(unsafe.Pointer(&memory[0])),
		mem: memory,
	}
}

// lastError returns an error describing the most recent error to happen to a
// session.
func (s *Session) lastError() error {
	return convertError(C.GoString(C.olm_session_last_error((*C.OlmSession)(s.int))))
}

// Clear clears the memory used to back this Session.
func (s *Session) Clear() error {
	r := C.olm_clear_session((*C.OlmSession)(s.int))
	if r == errorVal() {
		return s.lastError()
	}
	return nil
}

// pickleLen returns the number of bytes needed to store a session.
func (s *Session) pickleLen() uint {
	return uint(C.olm_pickle_session_length((*C.OlmSession)(s.int)))
}

// createOutboundRandomLen returns the number of random bytes needed to create
// an outbound session.
func (s *Session) createOutboundRandomLen() uint {
	return uint(C.olm_create_outbound_session_random_length((*C.OlmSession)(s.int)))
}

// idLen returns the length of the buffer needed to return the id for this
// session.
func (s *Session) idLen() uint {
	return uint(C.olm_session_id_length((*C.OlmSession)(s.int)))
}

// encryptRandomLen returns the number of random bytes needed to encrypt the
// next message.
func (s *Session) encryptRandomLen() uint {
	return uint(C.olm_encrypt_random_length((*C.OlmSession)(s.int)))
}

// encryptMsgLen returns the size of the next message in bytes for the given
// number of plain-text bytes.
func (s *Session) encryptMsgLen(plainTextLen int) uint {
	return uint(C.olm_encrypt_message_length((*C.OlmSession)(s.int), C.size_t(plainTextLen)))
}

// decryptMaxPlaintextLen returns the maximum number of bytes of plain-text a
// given message could decode to.  The actual size could be different due to
// padding.  Returns error on failure.  If the message base64 couldn't be
// decoded then the error will be "INVALID_BASE64".  If the message is for an
// unsupported version of the protocol then the error will be
// "BAD_MESSAGE_VERSION".  If the message couldn't be decoded then the error
// will be "BAD_MESSAGE_FORMAT".
func (s *Session) decryptMaxPlaintextLen(message string, msgType id.OlmMsgType) (uint, error) {
	if len(message) == 0 {
		return 0, EmptyInput
	}
	r := C.olm_decrypt_max_plaintext_length(
		(*C.OlmSession)(s.int),
		C.size_t(msgType),
		unsafe.Pointer(C.CString(message)),
		C.size_t(len(message)))
	if r == errorVal() {
		return 0, s.lastError()
	}
	return uint(r), nil
}

// Pickle returns a Session as a base64 string.  Encrypts the Session using the
// supplied key.
func (s *Session) Pickle(key []byte) []byte {
	if len(key) == 0 {
		panic(NoKeyProvided)
	}
	pickled := make([]byte, s.pickleLen())
	r := C.olm_pickle_session(
		(*C.OlmSession)(s.int),
		unsafe.Pointer(&key[0]),
		C.size_t(len(key)),
		unsafe.Pointer(&pickled[0]),
		C.size_t(len(pickled)))
	if r == errorVal() {
		panic(s.lastError())
	}
	return pickled[:r]
}

func (s *Session) Unpickle(pickled, key []byte) error {
	if len(key) == 0 {
		return NoKeyProvided
	}
	r := C.olm_unpickle_session(
		(*C.OlmSession)(s.int),
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
func (s *Session) GobEncode() ([]byte, error) {
	pickled := s.Pickle(pickleKey)
	length := base64.RawStdEncoding.DecodedLen(len(pickled))
	rawPickled := make([]byte, length)
	_, err := base64.RawStdEncoding.Decode(rawPickled, pickled)
	return rawPickled, err
}

// Deprecated
func (s *Session) GobDecode(rawPickled []byte) error {
	if s == nil || s.int == nil {
		*s = *NewBlankSession()
	}
	length := base64.RawStdEncoding.EncodedLen(len(rawPickled))
	pickled := make([]byte, length)
	base64.RawStdEncoding.Encode(pickled, rawPickled)
	return s.Unpickle(pickled, pickleKey)
}

// Deprecated
func (s *Session) MarshalJSON() ([]byte, error) {
	pickled := s.Pickle(pickleKey)
	quotes := make([]byte, len(pickled)+2)
	quotes[0] = '"'
	quotes[len(quotes)-1] = '"'
	copy(quotes[1:len(quotes)-1], pickled)
	return quotes, nil
}

// Deprecated
func (s *Session) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || len(data) == 0 || data[0] != '"' || data[len(data)-1] != '"' {
		return InputNotJSONString
	}
	if s == nil || s.int == nil {
		*s = *NewBlankSession()
	}
	return s.Unpickle(data[1:len(data)-1], pickleKey)
}

// Id returns an identifier for this Session.  Will be the same for both ends
// of the conversation.
func (s *Session) ID() id.SessionID {
	sessionID := make([]byte, s.idLen())
	r := C.olm_session_id(
		(*C.OlmSession)(s.int),
		unsafe.Pointer(&sessionID[0]),
		C.size_t(len(sessionID)))
	if r == errorVal() {
		panic(s.lastError())
	}
	return id.SessionID(sessionID)
}

// HasReceivedMessage returns true if this session has received any message.
func (s *Session) HasReceivedMessage() bool {
	switch C.olm_session_has_received_message((*C.OlmSession)(s.int)) {
	case 0:
		return false
	default:
		return true
	}
}

// MatchesInboundSession checks if the PRE_KEY message is for this in-bound
// Session.  This can happen if multiple messages are sent to this Account
// before this Account sends a message in reply.  Returns true if the session
// matches.  Returns false if the session does not match.  Returns error on
// failure.  If the base64 couldn't be decoded then the error will be
// "INVALID_BASE64".  If the message was for an unsupported protocol version
// then the error will be "BAD_MESSAGE_VERSION".  If the message couldn't be
// decoded then then the error will be "BAD_MESSAGE_FORMAT".
func (s *Session) MatchesInboundSession(oneTimeKeyMsg string) (bool, error) {
	if len(oneTimeKeyMsg) == 0 {
		return false, EmptyInput
	}
	r := C.olm_matches_inbound_session(
		(*C.OlmSession)(s.int),
		unsafe.Pointer(&([]byte(oneTimeKeyMsg))[0]),
		C.size_t(len(oneTimeKeyMsg)))
	if r == 1 {
		return true, nil
	} else if r == 0 {
		return false, nil
	} else { // if r == errorVal()
		return false, s.lastError()
	}
}

// MatchesInboundSessionFrom checks if the PRE_KEY message is for this in-bound
// Session.  This can happen if multiple messages are sent to this Account
// before this Account sends a message in reply.  Returns true if the session
// matches.  Returns false if the session does not match.  Returns error on
// failure.  If the base64 couldn't be decoded then the error will be
// "INVALID_BASE64".  If the message was for an unsupported protocol version
// then the error will be "BAD_MESSAGE_VERSION".  If the message couldn't be
// decoded then then the error will be "BAD_MESSAGE_FORMAT".
func (s *Session) MatchesInboundSessionFrom(theirIdentityKey, oneTimeKeyMsg string) (bool, error) {
	if len(theirIdentityKey) == 0 || len(oneTimeKeyMsg) == 0 {
		return false, EmptyInput
	}
	r := C.olm_matches_inbound_session_from(
		(*C.OlmSession)(s.int),
		unsafe.Pointer(&([]byte(theirIdentityKey))[0]),
		C.size_t(len(theirIdentityKey)),
		unsafe.Pointer(&([]byte(oneTimeKeyMsg))[0]),
		C.size_t(len(oneTimeKeyMsg)))
	if r == 1 {
		return true, nil
	} else if r == 0 {
		return false, nil
	} else { // if r == errorVal()
		return false, s.lastError()
	}
}

// EncryptMsgType returns the type of the next message that Encrypt will
// return.  Returns MsgTypePreKey if the message will be a PRE_KEY message.
// Returns MsgTypeMsg if the message will be a normal message.  Returns error
// on failure.
func (s *Session) EncryptMsgType() id.OlmMsgType {
	switch C.olm_encrypt_message_type((*C.OlmSession)(s.int)) {
	case C.size_t(id.OlmMsgTypePreKey):
		return id.OlmMsgTypePreKey
	case C.size_t(id.OlmMsgTypeMsg):
		return id.OlmMsgTypeMsg
	default:
		panic("olm_encrypt_message_type returned invalid result")
	}
}

// Encrypt encrypts a message using the Session.  Returns the encrypted message
// as base64.
func (s *Session) Encrypt(plaintext []byte) (id.OlmMsgType, []byte) {
	if len(plaintext) == 0 {
		panic(EmptyInput)
	}
	// Make the slice be at least length 1
	random := make([]byte, s.encryptRandomLen()+1)
	_, err := rand.Read(random)
	if err != nil {
		panic(NotEnoughGoRandom)
	}
	messageType := s.EncryptMsgType()
	message := make([]byte, s.encryptMsgLen(len(plaintext)))
	r := C.olm_encrypt(
		(*C.OlmSession)(s.int),
		unsafe.Pointer(&plaintext[0]),
		C.size_t(len(plaintext)),
		unsafe.Pointer(&random[0]),
		C.size_t(len(random)),
		unsafe.Pointer(&message[0]),
		C.size_t(len(message)))
	if r == errorVal() {
		panic(s.lastError())
	}
	return messageType, message[:r]
}

// Decrypt decrypts a message using the Session.  Returns the the plain-text on
// success.  Returns error on failure.  If the base64 couldn't be decoded then
// the error will be "INVALID_BASE64".  If the message is for an unsupported
// version of the protocol then the error will be "BAD_MESSAGE_VERSION".  If
// the message couldn't be decoded then the error will be BAD_MESSAGE_FORMAT".
// If the MAC on the message was invalid then the error will be
// "BAD_MESSAGE_MAC".
func (s *Session) Decrypt(message string, msgType id.OlmMsgType) ([]byte, error) {
	if len(message) == 0 {
		return nil, EmptyInput
	}
	decryptMaxPlaintextLen, err := s.decryptMaxPlaintextLen(message, msgType)
	if err != nil {
		return nil, err
	}
	messageCopy := []byte(message)
	plaintext := make([]byte, decryptMaxPlaintextLen)
	r := C.olm_decrypt(
		(*C.OlmSession)(s.int),
		C.size_t(msgType),
		unsafe.Pointer(&(messageCopy)[0]),
		C.size_t(len(messageCopy)),
		unsafe.Pointer(&plaintext[0]),
		C.size_t(len(plaintext)))
	if r == errorVal() {
		return nil, s.lastError()
	}
	return plaintext[:r], nil
}

// https://gitlab.matrix.org/matrix-org/olm/-/blob/3.2.8/include/olm/olm.h#L392-393
const maxDescribeSize = 600

// Describe generates a string describing the internal state of an olm session for debugging and logging purposes.
func (s *Session) Describe() string {
	desc := (*C.char)(C.malloc(C.size_t(maxDescribeSize)))
	defer C.free(unsafe.Pointer(desc))
	C.meowlm_session_describe(
		(*C.OlmSession)(s.int),
		desc,
		C.size_t(maxDescribeSize))
	return C.GoString(desc)
}
