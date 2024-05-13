package libolm

// #cgo LDFLAGS: -lolm -lstdc++
// #include <olm/olm.h>
import "C"

// errorVal returns the value that olm functions return if there was an error.
func errorVal() C.size_t {
	return C.olm_error()
}
