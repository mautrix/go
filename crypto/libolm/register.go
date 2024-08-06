package libolm

// #cgo LDFLAGS: -lolm -lstdc++
// #include <olm/olm.h>
import "C"
import "maunium.net/go/mautrix/crypto/olm"

var pickleKey = []byte("maunium.net/go/mautrix/crypto/olm")

func init() {
	olm.GetVersion = func() (major, minor, patch uint8) {
		C.olm_get_library_version(
			(*C.uint8_t)(&major),
			(*C.uint8_t)(&minor),
			(*C.uint8_t)(&patch))
		return 3, 2, 15
	}
	olm.SetPickleKeyImpl = func(key []byte) {
		pickleKey = key
	}
}
