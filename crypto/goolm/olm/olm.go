// olm provides the ratchet used by the olm protocol
package olm

import (
	"fmt"
	"io"

	"github.com/element-hq/mautrix-go/crypto/goolm"
	"github.com/element-hq/mautrix-go/crypto/goolm/cipher"
	"github.com/element-hq/mautrix-go/crypto/goolm/crypto"
	"github.com/element-hq/mautrix-go/crypto/goolm/libolmpickle"
	"github.com/element-hq/mautrix-go/crypto/goolm/message"
	"github.com/element-hq/mautrix-go/crypto/goolm/utilities"
)

const (
	olmPickleVersion uint8 = 1
)

const (
	maxReceiverChains     = 5
	maxSkippedMessageKeys = 40
	protocolVersion       = 3
	messageKeySeed        = 0x01

	maxMessageGap   = 2000
	sharedKeyLength = 32
)

// KdfInfo has the infos used for the kdf
var KdfInfo = struct {
	Root    []byte
	Ratchet []byte
}{
	Root:    []byte("OLM_ROOT"),
	Ratchet: []byte("OLM_RATCHET"),
}

var RatchetCipher = cipher.NewAESSHA256([]byte("OLM_KEYS"))

// Ratchet represents the olm ratchet as described in
//
// https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/olm.md
type Ratchet struct {
	// The root key is used to generate chain keys from the ephemeral keys.
	// A new root_key is derived each time a new chain is started.
	RootKey crypto.Curve25519PublicKey `json:"root_key"`

	// The sender chain is used to send messages. Each time a new ephemeral
	// key is received from the remote server we generate a new sender chain
	// with a new ephemeral key when we next send a message.
	SenderChains senderChain `json:"sender_chain"`

	// The receiver chain is used to decrypt received messages. We store the
	// last few chains so we can decrypt any out of order messages we haven't
	// received yet.
	// New chains are prepended for easier access.
	ReceiverChains []receiverChain `json:"receiver_chains"`

	// Storing the keys of missed messages for future use.
	// The order of the elements is not important.
	SkippedMessageKeys []skippedMessageKey `json:"skipped_message_keys"`
}

// New creates a new ratchet, setting the kdfInfos and cipher.
func New() *Ratchet {
	r := &Ratchet{}
	return r
}

// InitializeAsBob initializes this ratchet from a receiving point of view (only first message).
func (r *Ratchet) InitializeAsBob(sharedSecret []byte, theirRatchetKey crypto.Curve25519PublicKey) error {
	derivedSecretsReader := crypto.HKDFSHA256(sharedSecret, nil, KdfInfo.Root)
	derivedSecrets := make([]byte, 2*sharedKeyLength)
	if _, err := io.ReadFull(derivedSecretsReader, derivedSecrets); err != nil {
		return err
	}
	r.RootKey = derivedSecrets[0:sharedKeyLength]
	newReceiverChain := newReceiverChain(derivedSecrets[sharedKeyLength:], theirRatchetKey)
	r.ReceiverChains = append([]receiverChain{*newReceiverChain}, r.ReceiverChains...)
	return nil
}

// InitializeAsAlice initializes this ratchet from a sending point of view (only first message).
func (r *Ratchet) InitializeAsAlice(sharedSecret []byte, ourRatchetKey crypto.Curve25519KeyPair) error {
	derivedSecretsReader := crypto.HKDFSHA256(sharedSecret, nil, KdfInfo.Root)
	derivedSecrets := make([]byte, 2*sharedKeyLength)
	if _, err := io.ReadFull(derivedSecretsReader, derivedSecrets); err != nil {
		return err
	}
	r.RootKey = derivedSecrets[0:sharedKeyLength]
	newSenderChain := newSenderChain(derivedSecrets[sharedKeyLength:], ourRatchetKey)
	r.SenderChains = *newSenderChain
	return nil
}

// Encrypt encrypts the message in a message.Message with MAC. If reader is nil, crypto/rand is used for key generations.
func (r *Ratchet) Encrypt(plaintext []byte, reader io.Reader) ([]byte, error) {
	var err error
	if !r.SenderChains.IsSet {
		newRatchetKey, err := crypto.Curve25519GenerateKey(reader)
		if err != nil {
			return nil, err
		}
		newChainKey, err := r.advanceRootKey(newRatchetKey, r.ReceiverChains[0].ratchetKey())
		if err != nil {
			return nil, err
		}
		newSenderChain := newSenderChain(newChainKey, newRatchetKey)
		r.SenderChains = *newSenderChain
	}

	messageKey := r.createMessageKeys(r.SenderChains.chainKey())
	r.SenderChains.advance()

	encryptedText, err := RatchetCipher.Encrypt(messageKey.Key, plaintext)
	if err != nil {
		return nil, fmt.Errorf("cipher encrypt: %w", err)
	}

	message := &message.Message{}
	message.Version = protocolVersion
	message.Counter = messageKey.Index
	message.RatchetKey = r.SenderChains.ratchetKey().PublicKey
	message.Ciphertext = encryptedText
	//creating the mac is done in encode
	output, err := message.EncodeAndMAC(messageKey.Key, RatchetCipher)
	if err != nil {
		return nil, err
	}

	return output, nil
}

// Decrypt decrypts the ciphertext and verifies the MAC.  If reader is nil, crypto/rand is used for key generations.
func (r *Ratchet) Decrypt(input []byte) ([]byte, error) {
	message := &message.Message{}
	//The mac is not verified here, as we do not know the key yet
	err := message.Decode(input)
	if err != nil {
		return nil, err
	}
	if message.Version != protocolVersion {
		return nil, fmt.Errorf("decrypt: %w", goolm.ErrWrongProtocolVersion)
	}
	if !message.HasCounter || len(message.RatchetKey) == 0 || len(message.Ciphertext) == 0 {
		return nil, fmt.Errorf("decrypt: %w", goolm.ErrBadMessageFormat)
	}
	var receiverChainFromMessage *receiverChain
	for curChainIndex := range r.ReceiverChains {
		if r.ReceiverChains[curChainIndex].ratchetKey().Equal(message.RatchetKey) {
			receiverChainFromMessage = &r.ReceiverChains[curChainIndex]
			break
		}
	}
	var result []byte
	if receiverChainFromMessage == nil {
		//Advancing the chain is done in this method
		result, err = r.decryptForNewChain(message, input)
		if err != nil {
			return nil, err
		}
	} else if receiverChainFromMessage.chainKey().Index > message.Counter {
		// No need to advance the chain
		// Chain already advanced beyond the key for this message
		// Check if the message keys are in the skipped key list.
		foundSkippedKey := false
		for curSkippedIndex := range r.SkippedMessageKeys {
			if message.Counter == r.SkippedMessageKeys[curSkippedIndex].MKey.Index {
				// Found the key for this message. Check the MAC.
				verified, err := message.VerifyMACInline(r.SkippedMessageKeys[curSkippedIndex].MKey.Key, RatchetCipher, input)
				if err != nil {
					return nil, err
				}
				if !verified {
					return nil, fmt.Errorf("decrypt from skipped message keys: %w", goolm.ErrBadMAC)
				}
				result, err = RatchetCipher.Decrypt(r.SkippedMessageKeys[curSkippedIndex].MKey.Key, message.Ciphertext)
				if err != nil {
					return nil, fmt.Errorf("cipher decrypt: %w", err)
				}
				if len(result) != 0 {
					// Remove the key from the skipped keys now that we've
					// decoded the message it corresponds to.
					r.SkippedMessageKeys[curSkippedIndex] = r.SkippedMessageKeys[len(r.SkippedMessageKeys)-1]
					r.SkippedMessageKeys = r.SkippedMessageKeys[:len(r.SkippedMessageKeys)-1]
				}
				foundSkippedKey = true
			}
		}
		if !foundSkippedKey {
			return nil, fmt.Errorf("decrypt: %w", goolm.ErrMessageKeyNotFound)
		}
	} else {
		//Advancing the chain is done in this method
		result, err = r.decryptForExistingChain(receiverChainFromMessage, message, input)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// advanceRootKey created the next root key and returns the next chainKey
func (r *Ratchet) advanceRootKey(newRatchetKey crypto.Curve25519KeyPair, oldRatchetKey crypto.Curve25519PublicKey) (crypto.Curve25519PublicKey, error) {
	sharedSecret, err := newRatchetKey.SharedSecret(oldRatchetKey)
	if err != nil {
		return nil, err
	}
	derivedSecretsReader := crypto.HKDFSHA256(sharedSecret, r.RootKey, KdfInfo.Ratchet)
	derivedSecrets := make([]byte, 2*sharedKeyLength)
	if _, err := io.ReadFull(derivedSecretsReader, derivedSecrets); err != nil {
		return nil, err
	}
	r.RootKey = derivedSecrets[:sharedKeyLength]
	return derivedSecrets[sharedKeyLength:], nil
}

// createMessageKeys returns the messageKey derived from the chainKey
func (r Ratchet) createMessageKeys(chainKey chainKey) messageKey {
	res := messageKey{}
	res.Key = crypto.HMACSHA256(chainKey.Key, []byte{messageKeySeed})
	res.Index = chainKey.Index
	return res
}

// decryptForExistingChain returns the decrypted message by using the chain. The MAC of the rawMessage is verified.
func (r *Ratchet) decryptForExistingChain(chain *receiverChain, message *message.Message, rawMessage []byte) ([]byte, error) {
	if message.Counter < chain.CKey.Index {
		return nil, fmt.Errorf("decrypt: %w", goolm.ErrChainTooHigh)
	}
	// Limit the number of hashes we're prepared to compute
	if message.Counter-chain.CKey.Index > maxMessageGap {
		return nil, fmt.Errorf("decrypt from existing chain: %w", goolm.ErrMsgIndexTooHigh)
	}
	for chain.CKey.Index < message.Counter {
		messageKey := r.createMessageKeys(chain.chainKey())
		skippedKey := skippedMessageKey{
			MKey: messageKey,
			RKey: chain.ratchetKey(),
		}
		r.SkippedMessageKeys = append(r.SkippedMessageKeys, skippedKey)
		chain.advance()
	}
	messageKey := r.createMessageKeys(chain.chainKey())
	chain.advance()
	verified, err := message.VerifyMACInline(messageKey.Key, RatchetCipher, rawMessage)
	if err != nil {
		return nil, err
	}
	if !verified {
		return nil, fmt.Errorf("decrypt from existing chain: %w", goolm.ErrBadMAC)
	}
	return RatchetCipher.Decrypt(messageKey.Key, message.Ciphertext)
}

// decryptForNewChain returns the decrypted message by creating a new chain and advancing the root key.
func (r *Ratchet) decryptForNewChain(message *message.Message, rawMessage []byte) ([]byte, error) {
	// They shouldn't move to a new chain until we've sent them a message
	// acknowledging the last one
	if !r.SenderChains.IsSet {
		return nil, fmt.Errorf("decrypt for new chain: %w", goolm.ErrProtocolViolation)
	}
	// Limit the number of hashes we're prepared to compute
	if message.Counter > maxMessageGap {
		return nil, fmt.Errorf("decrypt for new chain: %w", goolm.ErrMsgIndexTooHigh)
	}

	newChainKey, err := r.advanceRootKey(r.SenderChains.ratchetKey(), message.RatchetKey)
	if err != nil {
		return nil, err
	}
	newChain := newReceiverChain(newChainKey, message.RatchetKey)
	r.ReceiverChains = append([]receiverChain{*newChain}, r.ReceiverChains...)
	/*
		They have started using a new ephemeral ratchet key.
		We needed to derive a new set of chain keys.
		We can discard our previous ephemeral ratchet key.
		We will generate a new key when we send the next message.
	*/
	r.SenderChains = senderChain{}

	decrypted, err := r.decryptForExistingChain(&r.ReceiverChains[0], message, rawMessage)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

// PickleAsJSON returns a ratchet as a base64 string encrypted using the supplied key. The unencrypted representation of the Account is in JSON format.
func (r Ratchet) PickleAsJSON(key []byte) ([]byte, error) {
	return utilities.PickleAsJSON(r, olmPickleVersion, key)
}

// UnpickleAsJSON updates a ratchet by a base64 encrypted string using the supplied key. The unencrypted representation has to be in JSON format.
func (r *Ratchet) UnpickleAsJSON(pickled, key []byte) error {
	return utilities.UnpickleAsJSON(r, pickled, key, olmPickleVersion)
}

// UnpickleLibOlm decodes the unencryted value and populates the Ratchet accordingly. It returns the number of bytes read.
func (r *Ratchet) UnpickleLibOlm(value []byte, includesChainIndex bool) (int, error) {
	//read ratchet data
	curPos := 0
	readBytes, err := r.RootKey.UnpickleLibOlm(value)
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	countSenderChains, readBytes, err := libolmpickle.UnpickleUInt32(value[curPos:]) //Length of sender chain
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	for i := uint32(0); i < countSenderChains; i++ {
		if i == 0 {
			//only first is stored
			readBytes, err := r.SenderChains.UnpickleLibOlm(value[curPos:])
			if err != nil {
				return 0, err
			}
			curPos += readBytes
			r.SenderChains.IsSet = true
		} else {
			dummy := senderChain{}
			readBytes, err := dummy.UnpickleLibOlm(value[curPos:])
			if err != nil {
				return 0, err
			}
			curPos += readBytes
		}
	}
	countReceivChains, readBytes, err := libolmpickle.UnpickleUInt32(value[curPos:]) //Length of recevier chain
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	r.ReceiverChains = make([]receiverChain, countReceivChains)
	for i := uint32(0); i < countReceivChains; i++ {
		readBytes, err := r.ReceiverChains[i].UnpickleLibOlm(value[curPos:])
		if err != nil {
			return 0, err
		}
		curPos += readBytes
	}
	countSkippedMessageKeys, readBytes, err := libolmpickle.UnpickleUInt32(value[curPos:]) //Length of skippedMessageKeys
	if err != nil {
		return 0, err
	}
	curPos += readBytes
	r.SkippedMessageKeys = make([]skippedMessageKey, countSkippedMessageKeys)
	for i := uint32(0); i < countSkippedMessageKeys; i++ {
		readBytes, err := r.SkippedMessageKeys[i].UnpickleLibOlm(value[curPos:])
		if err != nil {
			return 0, err
		}
		curPos += readBytes
	}
	// pickle v 0x80000001 includes a chain index; pickle v1 does not.
	if includesChainIndex {
		_, readBytes, err := libolmpickle.UnpickleUInt32(value[curPos:])
		if err != nil {
			return 0, err
		}
		curPos += readBytes
	}
	return curPos, nil
}

// PickleLibOlm encodes the ratchet into target. target has to have a size of at least PickleLen() and is written to from index 0.
// It returns the number of bytes written.
func (r Ratchet) PickleLibOlm(target []byte) (int, error) {
	if len(target) < r.PickleLen() {
		return 0, fmt.Errorf("pickle ratchet: %w", goolm.ErrValueTooShort)
	}
	written, err := r.RootKey.PickleLibOlm(target)
	if err != nil {
		return 0, fmt.Errorf("pickle ratchet: %w", err)
	}
	if r.SenderChains.IsSet {
		written += libolmpickle.PickleUInt32(1, target[written:]) //Length of sender chain, always 1
		writtenSender, err := r.SenderChains.PickleLibOlm(target[written:])
		if err != nil {
			return 0, fmt.Errorf("pickle ratchet: %w", err)
		}
		written += writtenSender
	} else {
		written += libolmpickle.PickleUInt32(0, target[written:]) //Length of sender chain
	}
	written += libolmpickle.PickleUInt32(uint32(len(r.ReceiverChains)), target[written:])
	for _, curChain := range r.ReceiverChains {
		writtenChain, err := curChain.PickleLibOlm(target[written:])
		if err != nil {
			return 0, fmt.Errorf("pickle ratchet: %w", err)
		}
		written += writtenChain
	}
	written += libolmpickle.PickleUInt32(uint32(len(r.SkippedMessageKeys)), target[written:])
	for _, curChain := range r.SkippedMessageKeys {
		writtenChain, err := curChain.PickleLibOlm(target[written:])
		if err != nil {
			return 0, fmt.Errorf("pickle ratchet: %w", err)
		}
		written += writtenChain
	}
	return written, nil
}

// PickleLen returns the actual number of bytes the pickled ratchet will have.
func (r Ratchet) PickleLen() int {
	length := r.RootKey.PickleLen()
	if r.SenderChains.IsSet {
		length += libolmpickle.PickleUInt32Len(1)
		length += r.SenderChains.PickleLen()
	} else {
		length += libolmpickle.PickleUInt32Len(0)
	}
	length += libolmpickle.PickleUInt32Len(uint32(len(r.ReceiverChains)))
	length += len(r.ReceiverChains) * receiverChain{}.PickleLen()
	length += libolmpickle.PickleUInt32Len(uint32(len(r.SkippedMessageKeys)))
	length += len(r.SkippedMessageKeys) * skippedMessageKey{}.PickleLen()
	return length
}

// PickleLen returns the minimum number of bytes the pickled ratchet must have.
func (r Ratchet) PickleLenMin() int {
	length := r.RootKey.PickleLen()
	length += libolmpickle.PickleUInt32Len(0)
	length += libolmpickle.PickleUInt32Len(0)
	length += libolmpickle.PickleUInt32Len(0)
	return length
}
