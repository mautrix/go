package olm

import (
	"fmt"

	"github.com/element-hq/mautrix-go/crypto/goolm"
	"github.com/element-hq/mautrix-go/crypto/goolm/crypto"
	"github.com/element-hq/mautrix-go/crypto/goolm/libolmpickle"
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

// PickleLibOlm encodes the chain key into target. target has to have a size of at least PickleLen() and is written to from index 0.
// It returns the number of bytes written.
func (r chainKey) PickleLibOlm(target []byte) (int, error) {
	if len(target) < r.PickleLen() {
		return 0, fmt.Errorf("pickle chain key: %w", goolm.ErrValueTooShort)
	}
	written, err := r.Key.PickleLibOlm(target)
	if err != nil {
		return 0, fmt.Errorf("pickle chain key: %w", err)
	}
	written += libolmpickle.PickleUInt32(r.Index, target[written:])
	return written, nil
}

// PickleLen returns the number of bytes the pickled chain key will have.
func (r chainKey) PickleLen() int {
	length := r.Key.PickleLen()
	length += libolmpickle.PickleUInt32Len(r.Index)
	return length
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

// PickleLibOlm encodes the chain into target. target has to have a size of at least PickleLen() and is written to from index 0.
// It returns the number of bytes written.
func (r senderChain) PickleLibOlm(target []byte) (int, error) {
	if len(target) < r.PickleLen() {
		return 0, fmt.Errorf("pickle sender chain: %w", goolm.ErrValueTooShort)
	}
	written, err := r.RKey.PickleLibOlm(target)
	if err != nil {
		return 0, fmt.Errorf("pickle sender chain: %w", err)
	}
	writtenChain, err := r.CKey.PickleLibOlm(target[written:])
	if err != nil {
		return 0, fmt.Errorf("pickle sender chain: %w", err)
	}
	written += writtenChain
	return written, nil
}

// PickleLen returns the number of bytes the pickled chain will have.
func (r senderChain) PickleLen() int {
	length := r.RKey.PickleLen()
	length += r.CKey.PickleLen()
	return length
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

// PickleLibOlm encodes the chain into target. target has to have a size of at least PickleLen() and is written to from index 0.
// It returns the number of bytes written.
func (r receiverChain) PickleLibOlm(target []byte) (int, error) {
	if len(target) < r.PickleLen() {
		return 0, fmt.Errorf("pickle sender chain: %w", goolm.ErrValueTooShort)
	}
	written, err := r.RKey.PickleLibOlm(target)
	if err != nil {
		return 0, fmt.Errorf("pickle sender chain: %w", err)
	}
	writtenChain, err := r.CKey.PickleLibOlm(target)
	if err != nil {
		return 0, fmt.Errorf("pickle sender chain: %w", err)
	}
	written += writtenChain
	return written, nil
}

// PickleLen returns the number of bytes the pickled chain will have.
func (r receiverChain) PickleLen() int {
	length := r.RKey.PickleLen()
	length += r.CKey.PickleLen()
	return length
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

// PickleLibOlm encodes the message key into target. target has to have a size of at least PickleLen() and is written to from index 0.
// It returns the number of bytes written.
func (m messageKey) PickleLibOlm(target []byte) (int, error) {
	if len(target) < m.PickleLen() {
		return 0, fmt.Errorf("pickle message key: %w", goolm.ErrValueTooShort)
	}
	written := 0
	if len(m.Key) != messageKeyLength {
		written += libolmpickle.PickleBytes(make([]byte, messageKeyLength), target)
	} else {
		written += libolmpickle.PickleBytes(m.Key, target)
	}
	written += libolmpickle.PickleUInt32(m.Index, target[written:])
	return written, nil
}

// PickleLen returns the number of bytes the pickled message key will have.
func (r messageKey) PickleLen() int {
	length := libolmpickle.PickleBytesLen(make([]byte, messageKeyLength))
	length += libolmpickle.PickleUInt32Len(r.Index)
	return length
}
