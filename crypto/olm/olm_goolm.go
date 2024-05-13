//go:build goolm

package olm

// Version returns the version number of the olm library.
func Version() (major, minor, patch uint8) {
	return 3, 2, 15
}

// SetPickleKey sets the global pickle key used when encoding structs with Gob or JSON.
func SetPickleKey(key []byte) {
	panic("gob and json encoding is deprecated and not supported with goolm")
}
