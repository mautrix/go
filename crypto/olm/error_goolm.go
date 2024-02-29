//go:build goolm

package olm

import (
	"errors"

	"github.com/element-hq/mautrix-go/crypto/goolm"
)

// Error codes from go-olm
var (
	EmptyInput         = goolm.ErrEmptyInput
	NoKeyProvided      = goolm.ErrNoKeyProvided
	NotEnoughGoRandom  = errors.New("couldn't get enough randomness from crypto/rand")
	SignatureNotFound  = errors.New("input JSON doesn't contain signature from specified device")
	InputNotJSONString = errors.New("input doesn't look like a JSON string")
)

// Error codes from olm code
var (
	UnknownMessageIndex = goolm.ErrRatchetNotAvailable
)
