package utilities

import (
	"encoding/json"

	"codeberg.org/DerLukas/goolm"
	"codeberg.org/DerLukas/goolm/cipher"
	"github.com/pkg/errors"
)

// PickleAsJSON returns an object as a base64 string encrypted using the supplied key. The unencrypted representation of the object is in JSON format.
func PickleAsJSON(object any, pickleVersion byte, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.Wrap(goolm.ErrNoKeyProvided, "pickle")
	}
	marshaled, err := json.Marshal(object)
	if err != nil {
		return nil, errors.Wrap(err, "pickle marshal")
	}
	marshaled = append([]byte{pickleVersion}, marshaled...)
	toEncrypt := make([]byte, len(marshaled))
	copy(toEncrypt, marshaled)
	//pad marshaled to get block size
	if len(marshaled)%cipher.PickleBlockSize() != 0 {
		padding := cipher.PickleBlockSize() - len(marshaled)%cipher.PickleBlockSize()
		toEncrypt = make([]byte, len(marshaled)+padding)
		copy(toEncrypt, marshaled)
	}
	encrypted, err := cipher.Pickle(key, toEncrypt)
	if err != nil {
		return nil, errors.Wrap(err, "pickle encrypt")
	}
	return encrypted, nil
}

// UnpickleAsJSON updates the object by a base64 encrypted string using the supplied key. The unencrypted representation has to be in JSON format.
func UnpickleAsJSON(object any, pickled, key []byte, pickleVersion byte) error {
	if len(key) == 0 {
		return errors.Wrap(goolm.ErrNoKeyProvided, "unpickle")
	}
	decrypted, err := cipher.Unpickle(key, pickled)
	if err != nil {
		return errors.Wrap(err, "unpickle decrypt")
	}
	//unpad decrypted so unmarshal works
	for i := len(decrypted) - 1; i >= 0; i-- {
		if decrypted[i] != 0 {
			decrypted = decrypted[:i+1]
			break
		}
	}
	if decrypted[0] != pickleVersion {
		return errors.Wrap(goolm.ErrWrongPickleVersion, "unpickle")
	}
	err = json.Unmarshal(decrypted[1:], object)
	if err != nil {
		return errors.Wrap(err, "unpickle unmarshal")
	}
	return nil
}
