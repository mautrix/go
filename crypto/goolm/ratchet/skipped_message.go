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

// UnpickleLibOlm unpickles the unencryted value and populates the skipped
// message keys accordingly.
func (r *skippedMessageKey) UnpickleLibOlm(decoder *libolmpickle.Decoder) (err error) {
	if err = r.RKey.UnpickleLibOlm(decoder); err != nil {
		return
	}
	return r.MKey.UnpickleLibOlm(decoder)
}

// PickleLibOlm pickles the skipped message key into the encoder.
func (r skippedMessageKey) PickleLibOlm(encoder *libolmpickle.Encoder) {
	r.RKey.PickleLibOlm(encoder)
	r.MKey.PickleLibOlm(encoder)
}
