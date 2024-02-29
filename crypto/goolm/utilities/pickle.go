package utilities

import (
	"encoding/json"
	"fmt"

	"github.com/element-hq/mautrix-go/crypto/goolm"
	"github.com/element-hq/mautrix-go/crypto/goolm/cipher"
)

// PickleAsJSON returns an object as a base64 string encrypted using the supplied key. The unencrypted representation of the object is in JSON format.
func PickleAsJSON(object any, pickleVersion byte, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("pickle: %w", goolm.ErrNoKeyProvided)
	}
	marshaled, err := json.Marshal(object)
	if err != nil {
		return nil, fmt.Errorf("pickle marshal: %w", err)
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
		return nil, fmt.Errorf("pickle encrypt: %w", err)
	}
	return encrypted, nil
}

// UnpickleAsJSON updates the object by a base64 encrypted string using the supplied key. The unencrypted representation has to be in JSON format.
func UnpickleAsJSON(object any, pickled, key []byte, pickleVersion byte) error {
	if len(key) == 0 {
		return fmt.Errorf("unpickle: %w", goolm.ErrNoKeyProvided)
	}
	decrypted, err := cipher.Unpickle(key, pickled)
	if err != nil {
		return fmt.Errorf("unpickle decrypt: %w", err)
	}
	//unpad decrypted so unmarshal works
	for i := len(decrypted) - 1; i >= 0; i-- {
		if decrypted[i] != 0 {
			decrypted = decrypted[:i+1]
			break
		}
	}
	if decrypted[0] != pickleVersion {
		return fmt.Errorf("unpickle: %w", goolm.ErrWrongPickleVersion)
	}
	err = json.Unmarshal(decrypted[1:], object)
	if err != nil {
		return fmt.Errorf("unpickle unmarshal: %w", err)
	}
	return nil
}
