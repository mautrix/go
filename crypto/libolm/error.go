package libolm

// #cgo LDFLAGS: -lolm -lstdc++
// #include <olm/olm.h>
import "C"

import (
	"fmt"

	"maunium.net/go/mautrix/crypto/olm"
)

var errorMap = map[string]error{
	"NOT_ENOUGH_RANDOM":         olm.ErrLibolmNotEnoughRandom,
	"OUTPUT_BUFFER_TOO_SMALL":   olm.ErrLibolmOutputBufferTooSmall,
	"BAD_MESSAGE_VERSION":       olm.ErrWrongProtocolVersion,
	"BAD_MESSAGE_FORMAT":        olm.ErrBadMessageFormat,
	"BAD_MESSAGE_MAC":           olm.ErrBadMAC,
	"BAD_MESSAGE_KEY_ID":        olm.ErrBadMessageKeyID,
	"INVALID_BASE64":            olm.ErrLibolmInvalidBase64,
	"BAD_ACCOUNT_KEY":           olm.ErrLibolmBadAccountKey,
	"UNKNOWN_PICKLE_VERSION":    olm.ErrUnknownOlmPickleVersion,
	"CORRUPTED_PICKLE":          olm.ErrLibolmCorruptedPickle,
	"BAD_SESSION_KEY":           olm.ErrLibolmBadSessionKey,
	"UNKNOWN_MESSAGE_INDEX":     olm.ErrUnknownMessageIndex,
	"BAD_LEGACY_ACCOUNT_PICKLE": olm.ErrLibolmBadLegacyAccountPickle,
	"BAD_SIGNATURE":             olm.ErrBadSignature,
	"INPUT_BUFFER_TOO_SMALL":    olm.ErrInputToSmall,
}

func convertError(errCode string) error {
	err, ok := errorMap[errCode]
	if ok {
		return err
	}
	return fmt.Errorf("unknown error: %s", errCode)
}
