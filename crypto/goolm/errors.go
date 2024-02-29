package goolm

import (
	"errors"
)

// Those are the most common used errors
var (
	ErrBadSignature         = errors.New("bad signature")
	ErrBadMAC               = errors.New("bad mac")
	ErrBadMessageFormat     = errors.New("bad message format")
	ErrBadVerification      = errors.New("bad verification")
	ErrWrongProtocolVersion = errors.New("wrong protocol version")
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
	ErrWrongPickleVersion   = errors.New("wrong pickle version")
	ErrValueTooShort        = errors.New("value too short")
	ErrInputToSmall         = errors.New("input too small (truncated?)")
	ErrOverflow             = errors.New("overflow")
)
