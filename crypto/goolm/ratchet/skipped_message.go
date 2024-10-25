package ratchet

import (
	"maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/crypto/goolm/libolmpickle"
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

// PickleLibOlm pickles the skipped message key into the encoder.
func (r skippedMessageKey) PickleLibOlm(encoder *libolmpickle.Encoder) {
	r.RKey.PickleLibOlm(encoder)
	r.MKey.PickleLibOlm(encoder)
}
