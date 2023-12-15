package goolm

import (
	"github.com/pkg/errors"
)

// Those are the most common used errors
var (
	ErrNoSigningKey         = errors.New("no signing key")
	ErrBadSignature         = errors.New("bad signature")
	ErrBadMAC               = errors.New("bad mac")
	ErrBadMessageFormat     = errors.New("bad message format")
	ErrBadVerification      = errors.New("bad verification")
	ErrWrongProtocolVersion = errors.New("wrong protocol version")
	ErrNoSessionKey         = errors.New("no session key")
	ErrEmptyInput           = errors.New("empty input")
	ErrNoKeyProvided        = errors.New("no key")
	ErrBadMessageKeyID      = errors.New("bad message key id")
	ErrRatchetNotAvailable  = errors.New("ratchet not available: attempt to decode a message whose index is earlier than our earliest known session key")
	ErrMsgIndexTooHigh      = errors.New("message index too high")
	ErrProtocolViolation    = errors.New("not protocol message order")
	ErrMessageKeyNotFound   = errors.New("message key not found")
	ErrChainTooHigh         = errors.New("chain index too high")
	ErrBadInput             = errors.New("bad input")
	ErrBadVersion           = errors.New("wrong version")
	ErrNotBlocksize         = errors.New("length != blocksize")
	ErrNotMultipleBlocksize = errors.New("length not a multiple of the blocksize")
	ErrBase64InvalidLength  = errors.New("base64 decode invalid length")
	ErrWrongPickleVersion   = errors.New("Wrong pickle version")
	ErrSignatureNotFound    = errors.New("signature not found")
	ErrNotEnoughGoRandom    = errors.New("Not enough random data available")
	ErrValueTooShort        = errors.New("value too short")
	ErrInputToSmall         = errors.New("input too small (truncated?)")
	ErrOverflow             = errors.New("overflow")
	ErrBadBase64            = errors.New("Bad base64")
)
