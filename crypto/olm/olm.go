//go:build !goolm

package olm

// #cgo LDFLAGS: -lolm -lstdc++
// #include <olm/olm.h>
import "C"
import (
	"github.com/element-hq/mautrix-go/id"
)

// Signatures is the data structure used to sign JSON objects.
type Signatures map[id.UserID]map[id.DeviceKeyID]string

// Version returns the version number of the olm library.
func Version() (major, minor, patch uint8) {
	C.olm_get_library_version(
		(*C.uint8_t)(&major),
		(*C.uint8_t)(&minor),
		(*C.uint8_t)(&patch))
	return
}

// errorVal returns the value that olm functions return if there was an error.
func errorVal() C.size_t {
	return C.olm_error()
}

var pickleKey = []byte("github.com/element-hq/mautrix-go/crypto/olm")

// SetPickleKey sets the global pickle key used when encoding structs with Gob or JSON.
func SetPickleKey(key []byte) {
	pickleKey = key
}
