// megolm provides the ratchet used by the megolm protocol
package megolm

import (
	"crypto/rand"
	"fmt"

	"github.com/element-hq/mautrix-go/crypto/goolm"
	"github.com/element-hq/mautrix-go/crypto/goolm/cipher"
	"github.com/element-hq/mautrix-go/crypto/goolm/crypto"
	"github.com/element-hq/mautrix-go/crypto/goolm/libolmpickle"
	"github.com/element-hq/mautrix-go/crypto/goolm/message"
	"github.com/element-hq/mautrix-go/crypto/goolm/utilities"
)

const (
	megolmPickleVersion uint8 = 1
)

const (
	protocolVersion   = 3
	RatchetParts      = 4       // number of ratchet parts
	RatchetPartLength = 256 / 8 // length of each ratchet part in bytes
)

var RatchetCipher = cipher.NewAESSHA256([]byte("MEGOLM_KEYS"))

// hasKeySeed are the seed for the different ratchet parts
var hashKeySeeds [RatchetParts][]byte = [RatchetParts][]byte{
	{0x00},
	{0x01},
	{0x02},
	{0x03},
}

// Ratchet represents the megolm ratchet as described in
//
// https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/megolm.md
type Ratchet struct {
	Data    [RatchetParts * RatchetPartLength]byte `json:"data"`
	Counter uint32                                 `json:"counter"`
}

// New creates a new ratchet with counter set to counter and the ratchet data set to data.
func New(counter uint32, data [RatchetParts * RatchetPartLength]byte) (*Ratchet, error) {
	m := &Ratchet{
		Counter: counter,
		Data:    data,
	}
	return m, nil
}

// NewWithRandom creates a new ratchet with counter set to counter an the data filled with random values.
func NewWithRandom(counter uint32) (*Ratchet, error) {
	var data [RatchetParts * RatchetPartLength]byte
	_, err := rand.Read(data[:])
	if err != nil {
		return nil, err
	}
	return New(counter, data)
}

// rehashPart rehases the part of the ratchet data with the base defined as from storing into the target to.
func (m *Ratchet) rehashPart(from, to int) {
	newData := crypto.HMACSHA256(m.Data[from*RatchetPartLength:from*RatchetPartLength+RatchetPartLength], hashKeySeeds[to])
	copy(m.Data[to*RatchetPartLength:], newData[:RatchetPartLength])
}

// Advance advances the ratchet one step.
func (m *Ratchet) Advance() {
	var mask uint32 = 0x00FFFFFF
	var h int
	m.Counter++

	// figure out how much we need to rekey
	for h < RatchetParts {
		if (m.Counter & mask) == 0 {
			break
		}
		h++
		mask >>= 8
	}

	// now update R(h)...R(3) based on R(h)
	for i := RatchetParts - 1; i >= h; i-- {
		m.rehashPart(h, i)
	}
}

// AdvanceTo advances the ratchet so that the ratchet counter = target
func (m *Ratchet) AdvanceTo(target uint32) {
	//starting with R0, see if we need to update each part of the hash
	for j := 0; j < RatchetParts; j++ {
		shift := uint32((RatchetParts - j - 1) * 8)
		mask := (^uint32(0)) << shift

		// how many times do we need to rehash this part?
		// '& 0xff' ensures we handle integer wraparound correctly
		steps := ((target >> shift) - m.Counter>>shift) & uint32(0xff)

		if steps == 0 {
			/*
				deal with the edge case where m.Counter is slightly larger
				than target. This should only happen for R(0), and implies
				that target has wrapped around and we need to advance R(0)
				256 times.
			*/
			if target < m.Counter {
				steps = 0x100
			} else {
				continue
			}
		}
		//	for all but the last step, we can just bump R(j) without regard to R(j+1)...R(3).
		for steps > 1 {
			m.rehashPart(j, j)
			steps--
		}
		/*
			on the last step we also need to bump R(j+1)...R(3).

			(Theoretically, we could skip bumping R(j+2) if we're going to bump
			R(j+1) again, but the code to figure that out is a bit baroque and
			doesn't save us much).
		*/
		for k := 3; k >= j; k-- {
			m.rehashPart(j, k)
		}
		m.Counter = target & mask
	}
}

// Encrypt encrypts the message in a message.GroupMessage with MAC and signature.
// The output is base64 encoded.
func (r *Ratchet) Encrypt(plaintext []byte, key *crypto.Ed25519KeyPair) ([]byte, error) {
	var err error
	encryptedText, err := RatchetCipher.Encrypt(r.Data[:], plaintext)
	if err != nil {
		return nil, fmt.Errorf("cipher encrypt: %w", err)
	}

	message := &message.GroupMessage{}
	message.Version = protocolVersion
	message.MessageIndex = r.Counter
	message.Ciphertext = encryptedText
	//creating the mac and signing is done in encode
	output, err := message.EncodeAndMacAndSign(r.Data[:], RatchetCipher, key)
	if err != nil {
		return nil, err
	}
	r.Advance()
	return output, nil
}

// SessionSharingMessage creates a message in the session sharing format.
func (r Ratchet) SessionSharingMessage(key crypto.Ed25519KeyPair) ([]byte, error) {
	m := message.MegolmSessionSharing{}
	m.Counter = r.Counter
	m.RatchetData = r.Data
	encoded := m.EncodeAndSign(key)
	return goolm.Base64Encode(encoded), nil
}

// SessionExportMessage creates a message in the session export format.
func (r Ratchet) SessionExportMessage(key crypto.Ed25519PublicKey) ([]byte, error) {
	m := message.MegolmSessionExport{}
	m.Counter = r.Counter
	m.RatchetData = r.Data
	m.PublicKey = key
	encoded := m.Encode()
	return goolm.Base64Encode(encoded), nil
}

// Decrypt decrypts the ciphertext and verifies the MAC but not the signature.
func (r Ratchet) Decrypt(ciphertext []byte, signingkey *crypto.Ed25519PublicKey, msg *message.GroupMessage) ([]byte, error) {
	//verify mac
	verifiedMAC, err := msg.VerifyMACInline(r.Data[:], RatchetCipher, ciphertext)
	if err != nil {
		return nil, err
	}
	if !verifiedMAC {
		return nil, fmt.Errorf("decrypt: %w", goolm.ErrBadMAC)
	}

	return RatchetCipher.Decrypt(r.Data[:], msg.Ciphertext)
}

// PickleAsJSON returns a ratchet as a base64 string encrypted using the supplied key. The unencrypted representation of the Account is in JSON format.
func (r Ratchet) PickleAsJSON(key []byte) ([]byte, error) {
	return utilities.PickleAsJSON(r, megolmPickleVersion, key)
}

// UnpickleAsJSON updates a ratchet by a base64 encrypted string using the supplied key. The unencrypted representation has to be in JSON format.
func (r *Ratchet) UnpickleAsJSON(pickled, key []byte) error {
	return utilities.UnpickleAsJSON(r, pickled, key, megolmPickleVersion)
}

// UnpickleLibOlm decodes the unencryted value and populates the Ratchet accordingly. It returns the number of bytes read.
func (r *Ratchet) UnpickleLibOlm(unpickled []byte) (int, error) {
	//read ratchet data
	curPos := 0
	ratchetData, readBytes, err := libolmpickle.UnpickleBytes(unpickled, RatchetParts*RatchetPartLength)
	if err != nil {
		return 0, err
	}
	copy(r.Data[:], ratchetData)
	curPos += readBytes
	//Read counter
	counter, readBytes, err := libolmpickle.UnpickleUInt32(unpickled[curPos:])
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	r.Counter = counter
	return curPos, nil
}

// PickleLibOlm encodes the ratchet into target. target has to have a size of at least PickleLen() and is written to from index 0.
// It returns the number of bytes written.
func (r Ratchet) PickleLibOlm(target []byte) (int, error) {
	if len(target) < r.PickleLen() {
		return 0, fmt.Errorf("pickle account: %w", goolm.ErrValueTooShort)
	}
	written := libolmpickle.PickleBytes(r.Data[:], target)
	written += libolmpickle.PickleUInt32(r.Counter, target[written:])
	return written, nil
}

// PickleLen returns the number of bytes the pickled ratchet will have.
func (r Ratchet) PickleLen() int {
	length := libolmpickle.PickleBytesLen(r.Data[:])
	length += libolmpickle.PickleUInt32Len(r.Counter)
	return length
}
