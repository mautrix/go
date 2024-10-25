package ratchet

import (
	"maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/crypto/goolm/libolmpickle"
)

const (
	chainKeySeed     = 0x02
	messageKeyLength = 32
)

// chainKey wraps the index and the public key
type chainKey struct {
	Index uint32                     `json:"index"`
	Key   crypto.Curve25519PublicKey `json:"key"`
}

// advance advances the chain
func (c *chainKey) advance() {
	c.Key = crypto.HMACSHA256(c.Key, []byte{chainKeySeed})
	c.Index++
}

// UnpickleLibOlm decodes the unencryted value and populates the chain key accordingly. It returns the number of bytes read.
func (r *chainKey) UnpickleLibOlm(value []byte) (int, error) {
	curPos := 0
	readBytes, err := r.Key.UnpickleLibOlm(value)
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	r.Index, readBytes, err = libolmpickle.UnpickleUInt32(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	return curPos, nil
}

// PickleLibOlm pickles the chain key into the encoder.
func (r chainKey) PickleLibOlm(encoder *libolmpickle.Encoder) {
	r.Key.PickleLibOlm(encoder)
	encoder.WriteUInt32(r.Index)
}

// senderChain is a chain for sending messages
type senderChain struct {
	RKey  crypto.Curve25519KeyPair `json:"ratchet_key"`
	CKey  chainKey                 `json:"chain_key"`
	IsSet bool                     `json:"set"`
}

// newSenderChain returns a sender chain initialized with chainKey and ratchet key pair.
func newSenderChain(key crypto.Curve25519PublicKey, ratchet crypto.Curve25519KeyPair) *senderChain {
	return &senderChain{
		RKey: ratchet,
		CKey: chainKey{
			Index: 0,
			Key:   key,
		},
		IsSet: true,
	}
}

// advance advances the chain
func (s *senderChain) advance() {
	s.CKey.advance()
}

// ratchetKey returns the ratchet key pair.
func (s senderChain) ratchetKey() crypto.Curve25519KeyPair {
	return s.RKey
}

// chainKey returns the current chainKey.
func (s senderChain) chainKey() chainKey {
	return s.CKey
}

// UnpickleLibOlm decodes the unencryted value and populates the chain accordingly. It returns the number of bytes read.
func (r *senderChain) UnpickleLibOlm(value []byte) (int, error) {
	curPos := 0
	readBytes, err := r.RKey.UnpickleLibOlm(value)
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	readBytes, err = r.CKey.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	return curPos, nil
}

// PickleLibOlm pickles the sender chain into the encoder.
func (r senderChain) PickleLibOlm(encoder *libolmpickle.Encoder) {
	if r.IsSet {
		encoder.WriteUInt32(1) // Length of the sender chain (1 if set)
		r.RKey.PickleLibOlm(encoder)
		r.CKey.PickleLibOlm(encoder)
	} else {
		encoder.WriteUInt32(0)
	}
}

// senderChain is a chain for receiving messages
type receiverChain struct {
	RKey crypto.Curve25519PublicKey `json:"ratchet_key"`
	CKey chainKey                   `json:"chain_key"`
}

// newReceiverChain returns a receiver chain initialized with chainKey and ratchet public key.
func newReceiverChain(chain crypto.Curve25519PublicKey, ratchet crypto.Curve25519PublicKey) *receiverChain {
	return &receiverChain{
		RKey: ratchet,
		CKey: chainKey{
			Index: 0,
			Key:   chain,
		},
	}
}

// advance advances the chain
func (s *receiverChain) advance() {
	s.CKey.advance()
}

// ratchetKey returns the ratchet public key.
func (s receiverChain) ratchetKey() crypto.Curve25519PublicKey {
	return s.RKey
}

// chainKey returns the current chainKey.
func (s receiverChain) chainKey() chainKey {
	return s.CKey
}

// UnpickleLibOlm decodes the unencryted value and populates the chain accordingly. It returns the number of bytes read.
func (r *receiverChain) UnpickleLibOlm(value []byte) (int, error) {
	curPos := 0
	readBytes, err := r.RKey.UnpickleLibOlm(value)
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	readBytes, err = r.CKey.UnpickleLibOlm(value[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	return curPos, nil
}

// PickleLibOlm pickles the receiver chain into the encoder.
func (r receiverChain) PickleLibOlm(encoder *libolmpickle.Encoder) {
	r.RKey.PickleLibOlm(encoder)
	r.CKey.PickleLibOlm(encoder)
}

// messageKey wraps the index and the key of a message
type messageKey struct {
	Index uint32 `json:"index"`
	Key   []byte `json:"key"`
}

// UnpickleLibOlm decodes the unencryted value and populates the message key accordingly. It returns the number of bytes read.
func (m *messageKey) UnpickleLibOlm(value []byte) (int, error) {
	curPos := 0
	ratchetKey, readBytes, err := libolmpickle.UnpickleBytes(value, messageKeyLength)
	if err != nil {
		return 0, err
	}
	m.Key = ratchetKey
	curPos += readBytes
	keyID, readBytes, err := libolmpickle.UnpickleUInt32(value[:curPos])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	m.Index = keyID
	return curPos, nil
}

// PickleLibOlm pickles the message key into the encoder.
func (m messageKey) PickleLibOlm(encoder *libolmpickle.Encoder) {
	if len(m.Key) == messageKeyLength {
		encoder.Write(m.Key)
	} else {
		encoder.WriteEmptyBytes(messageKeyLength)
	}
	encoder.WriteUInt32(m.Index)
}
