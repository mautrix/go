package libolm

// #cgo LDFLAGS: -lolm -lstdc++
// #include <olm/olm.h>
import "C"
import (
	"unsafe"

	"maunium.net/go/mautrix/crypto/olm"
)

var pickleKey = []byte("maunium.net/go/mautrix/crypto/olm")

func init() {
	olm.GetVersion = func() (major, minor, patch uint8) {
		C.olm_get_library_version(
			(*C.uint8_t)(unsafe.Pointer(&major)),
			(*C.uint8_t)(unsafe.Pointer(&minor)),
			(*C.uint8_t)(unsafe.Pointer(&patch)))
		return 3, 2, 15
	}
	olm.SetPickleKeyImpl = func(key []byte) {
		pickleKey = key
	}
}
