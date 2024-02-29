package message

import (
	"encoding/binary"
	"fmt"

	"github.com/element-hq/mautrix-go/crypto/goolm"
	"github.com/element-hq/mautrix-go/crypto/goolm/crypto"
)

const (
	sessionSharingVersion = 0x02
)

// MegolmSessionSharing represents a message in the session sharing format.
type MegolmSessionSharing struct {
	Counter     uint32                  `json:"counter"`
	RatchetData [128]byte               `json:"data"`
	PublicKey   crypto.Ed25519PublicKey `json:"-"` //only used when decrypting messages
}

// Encode returns the encoded message in the correct format with the signature by key appended.
func (s MegolmSessionSharing) EncodeAndSign(key crypto.Ed25519KeyPair) []byte {
	output := make([]byte, 229)
	output[0] = sessionSharingVersion
	binary.BigEndian.PutUint32(output[1:], s.Counter)
	copy(output[5:], s.RatchetData[:])
	copy(output[133:], key.PublicKey)
	signature := key.Sign(output[:165])
	copy(output[165:], signature)
	return output
}

// VerifyAndDecode verifies the input and populates the struct with the data encoded in input.
func (s *MegolmSessionSharing) VerifyAndDecode(input []byte) error {
	if len(input) != 229 {
		return fmt.Errorf("verify: %w", goolm.ErrBadInput)
	}
	publicKey := crypto.Ed25519PublicKey(input[133:165])
	if !publicKey.Verify(input[:165], input[165:]) {
		return fmt.Errorf("verify: %w", goolm.ErrBadVerification)
	}
	s.PublicKey = publicKey
	if input[0] != sessionSharingVersion {
		return fmt.Errorf("verify: %w", goolm.ErrBadVersion)
	}
	s.Counter = binary.BigEndian.Uint32(input[1:5])
	copy(s.RatchetData[:], input[5:133])
	return nil
}
