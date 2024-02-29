package olm

import (
	"fmt"

	"github.com/element-hq/mautrix-go/crypto/goolm"
	"github.com/element-hq/mautrix-go/crypto/goolm/crypto"
)

// skippedMessageKey stores a skipped message key
type skippedMessageKey struct {
	RKey crypto.Curve25519PublicKey `json:"ratchet_key"`
	MKey messageKey                 `json:"message_key"`
}

// UnpickleLibOlm decodes the unencryted value and populates the chain accordingly. It returns the number of bytes read.
func (r *skippedMessageKey) UnpickleLibOlm(value []byte) (int, error) {
	curPos := 0
	readBytes, err := r.RKey.UnpickleLibOlm(value)
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	readBytes, err = r.MKey.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	return curPos, nil
}

// PickleLibOlm encodes the chain into target. target has to have a size of at least PickleLen() and is written to from index 0.
// It returns the number of bytes written.
func (r skippedMessageKey) PickleLibOlm(target []byte) (int, error) {
	if len(target) < r.PickleLen() {
		return 0, fmt.Errorf("pickle sender chain: %w", goolm.ErrValueTooShort)
	}
	written, err := r.RKey.PickleLibOlm(target)
	if err != nil {
		return 0, fmt.Errorf("pickle sender chain: %w", err)
	}
	writtenChain, err := r.MKey.PickleLibOlm(target)
	if err != nil {
		return 0, fmt.Errorf("pickle sender chain: %w", err)
	}
	written += writtenChain
	return written, nil
}

// PickleLen returns the number of bytes the pickled chain will have.
func (r skippedMessageKey) PickleLen() int {
	length := r.RKey.PickleLen()
	length += r.MKey.PickleLen()
	return length
}
