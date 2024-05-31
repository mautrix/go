package libolm

// #cgo LDFLAGS: -lolm -lstdc++
// #include <olm/olm.h>
import "C"

import (
	"fmt"

	"maunium.net/go/mautrix/crypto/olm"
)

var errorMap = map[string]error{
	"NOT_ENOUGH_RANDOM":         olm.NotEnoughRandom,
	"OUTPUT_BUFFER_TOO_SMALL":   olm.OutputBufferTooSmall,
	"BAD_MESSAGE_VERSION":       olm.BadMessageVersion,
	"BAD_MESSAGE_FORMAT":        olm.BadMessageFormat,
	"BAD_MESSAGE_MAC":           olm.BadMessageMAC,
	"BAD_MESSAGE_KEY_ID":        olm.BadMessageKeyID,
	"INVALID_BASE64":            olm.InvalidBase64,
	"BAD_ACCOUNT_KEY":           olm.BadAccountKey,
	"UNKNOWN_PICKLE_VERSION":    olm.UnknownPickleVersion,
	"CORRUPTED_PICKLE":          olm.CorruptedPickle,
	"BAD_SESSION_KEY":           olm.BadSessionKey,
	"UNKNOWN_MESSAGE_INDEX":     olm.UnknownMessageIndex,
	"BAD_LEGACY_ACCOUNT_PICKLE": olm.BadLegacyAccountPickle,
	"BAD_SIGNATURE":             olm.BadSignature,
	"INPUT_BUFFER_TOO_SMALL":    olm.InputBufferTooSmall,
}

func convertError(errCode string) error {
	err, ok := errorMap[errCode]
	if ok {
		return err
	}
	return fmt.Errorf("unknown error: %s", errCode)
}
