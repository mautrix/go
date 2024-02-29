//go:build goolm

package olm

import (
	"github.com/element-hq/mautrix-go/id"
)

// Signatures is the data structure used to sign JSON objects.
type Signatures map[id.UserID]map[id.DeviceKeyID]string

// Version returns the version number of the olm library.
func Version() (major, minor, patch uint8) {
	return 3, 2, 15
}

// SetPickleKey sets the global pickle key used when encoding structs with Gob or JSON.
func SetPickleKey(key []byte) {
	panic("gob and json encoding is deprecated and not supported with goolm")
}
