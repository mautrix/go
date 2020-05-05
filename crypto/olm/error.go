package olm

import (
	"errors"
	"fmt"
)

// Error codes from go-olm
var (
	EmptyInput         = errors.New("empty input")
	NoKeyProvided      = errors.New("no pickle key provided")
	NotEnoughGoRandom  = errors.New("couldn't get enough randomness from crypto/rand")
	SignatureNotFound  = errors.New("input JSON doesn't contain signature from specified device")
	InputNotJSONString = errors.New("input doesn't look like a JSON string")
)

// Error codes from olm code
var (
	NotEnoughRandom        = errors.New("not enough entropy was supplied")
	OutputBufferTooSmall   = errors.New("supplied output buffer is too small")
	BadMessageVersion      = errors.New("the message version is unsupported")
	BadMessageFormat       = errors.New("the message couldn't be decoded")
	BadMessageMAC          = errors.New("the message couldn't be decrypted")
	BadMessageKeyID        = errors.New("the message references an unknown key ID")
	InvalidBase64          = errors.New("the input base64 was invalid")
	BadAccountKey          = errors.New("the supplied account key is invalid")
	UnknownPickleVersion   = errors.New("the pickled object is too new")
	CorruptedPickle        = errors.New("the pickled object couldn't be decoded")
	BadSessionKey          = errors.New("attempt to initialise an inbound group session from an invalid session key")
	UnknownMessageIndex    = errors.New("attempt to decode a message whose index is earlier than our earliest known session key")
	BadLegacyAccountPickle = errors.New("attempt to unpickle an account which uses pickle version 1")
	BadSignature           = errors.New("received message had a bad signature")
	InputBufferTooSmall    = errors.New("the input data was too small to be valid")
)

var errorMap = map[string]error{
	"NOT_ENOUGH_RANDOM":         NotEnoughRandom,
	"OUTPUT_BUFFER_TOO_SMALL":   OutputBufferTooSmall,
	"BAD_MESSAGE_VERSION":       BadMessageVersion,
	"BAD_MESSAGE_FORMAT":        BadMessageFormat,
	"BAD_MESSAGE_MAC":           BadMessageMAC,
	"BAD_MESSAGE_KEY_ID":        BadMessageKeyID,
	"INVALID_BASE64":            InvalidBase64,
	"BAD_ACCOUNT_KEY":           BadAccountKey,
	"UNKNOWN_PICKLE_VERSION":    UnknownPickleVersion,
	"CORRUPTED_PICKLE":          CorruptedPickle,
	"BAD_SESSION_KEY":           BadSessionKey,
	"UNKNOWN_MESSAGE_INDEX":     UnknownMessageIndex,
	"BAD_LEGACY_ACCOUNT_PICKLE": BadLegacyAccountPickle,
	"BAD_SIGNATURE":             BadSignature,
	"INPUT_BUFFER_TOO_SMALL":    InputBufferTooSmall,
}

func convertError(errCode string) error {
	err, ok := errorMap[errCode]
	if ok {
		return err
	}
	return fmt.Errorf("unknown error: %s", errCode)
}
