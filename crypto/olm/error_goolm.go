//go:build goolm

package olm

import (
	"errors"
)

// Error codes from go-olm
var (
	ErrEmptyInput         = errors.New("empty input")
	ErrNoKeyProvided      = errors.New("no pickle key provided")
	ErrNotEnoughGoRandom  = errors.New("couldn't get enough randomness from crypto/rand")
	ErrSignatureNotFound  = errors.New("input JSON doesn't contain signature from specified device")
	ErrInputNotJSONString = errors.New("input doesn't look like a JSON string")
)
