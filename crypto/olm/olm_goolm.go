//go:build goolm

package olm

import (
	"codeberg.org/DerLukas/goolm"
	"maunium.net/go/mautrix/id"
)

// Signatures is the data structure used to sign JSON objects.
type Signatures map[id.UserID]map[id.DeviceKeyID]string

// Version returns the version number of the olm library.
func Version() (major, minor, patch uint8) {
	return goolm.GetLibaryVersion()
}

var pickleKey = []byte("maunium.net/go/mautrix/crypto/olm")

// SetPickleKey sets the global pickle key used when encoding structs with Gob or JSON.
func SetPickleKey(key []byte) {
	pickleKey = key
}
