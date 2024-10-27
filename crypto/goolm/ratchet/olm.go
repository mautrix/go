// Package ratchet provides the ratchet used by the olm protocol
package ratchet

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"maunium.net/go/mautrix/crypto/goolm/aessha2"
	"maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/crypto/goolm/libolmpickle"
	"maunium.net/go/mautrix/crypto/goolm/message"
	"maunium.net/go/mautrix/crypto/olm"
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

var olmKeysKDFInfo = []byte("OLM_KEYS")

// KdfInfo has the infos used for the kdf
var KdfInfo = struct {
	Root    []byte
	Ratchet []byte
}{
	Root:    []byte("OLM_ROOT"),
	Ratchet: []byte("OLM_RATCHET"),
}

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
	return &Ratchet{}
}

// InitializeAsBob initializes this ratchet from a receiving point of view (only first message).
func (r *Ratchet) InitializeAsBob(sharedSecret []byte, theirRatchetKey crypto.Curve25519PublicKey) error {
	derivedSecretsReader := hkdf.New(sha256.New, sharedSecret, nil, KdfInfo.Root)
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
	derivedSecretsReader := hkdf.New(sha256.New, sharedSecret, nil, KdfInfo.Root)
	derivedSecrets := make([]byte, 2*sharedKeyLength)
	if _, err := io.ReadFull(derivedSecretsReader, derivedSecrets); err != nil {
		return err
	}
	r.RootKey = derivedSecrets[0:sharedKeyLength]
	newSenderChain := newSenderChain(derivedSecrets[sharedKeyLength:], ourRatchetKey)
	r.SenderChains = *newSenderChain
	return nil
}

// Encrypt encrypts the message in a message.Message with MAC.
func (r *Ratchet) Encrypt(plaintext []byte) ([]byte, error) {
	var err error
	if !r.SenderChains.IsSet {
		newRatchetKey, err := crypto.Curve25519GenerateKey()
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

	cipher, err := aessha2.NewAESSHA2(messageKey.Key, olmKeysKDFInfo)
	if err != nil {
		return nil, err
	}
	encryptedText, err := cipher.Encrypt(plaintext)
	if err != nil {
		return nil, fmt.Errorf("cipher encrypt: %w", err)
	}

	message := &message.Message{}
	message.Version = protocolVersion
	message.Counter = messageKey.Index
	message.RatchetKey = r.SenderChains.ratchetKey().PublicKey
	message.Ciphertext = encryptedText
	//creating the mac is done in encode
	return message.EncodeAndMAC(cipher)
}

// Decrypt decrypts the ciphertext and verifies the MAC.
func (r *Ratchet) Decrypt(input []byte) ([]byte, error) {
	message := &message.Message{}
	//The mac is not verified here, as we do not know the key yet
	err := message.Decode(input)
	if err != nil {
		return nil, err
	}
	if message.Version != protocolVersion {
		return nil, fmt.Errorf("decrypt: %w", olm.ErrWrongProtocolVersion)
	}
	if !message.HasCounter || len(message.RatchetKey) == 0 || len(message.Ciphertext) == 0 {
		return nil, fmt.Errorf("decrypt: %w", olm.ErrBadMessageFormat)
	}
	var receiverChainFromMessage *receiverChain
	for curChainIndex := range r.ReceiverChains {
		if r.ReceiverChains[curChainIndex].ratchetKey().Equal(message.RatchetKey) {
			receiverChainFromMessage = &r.ReceiverChains[curChainIndex]
			break
		}
	}
	if receiverChainFromMessage == nil {
		//Advancing the chain is done in this method
		return r.decryptForNewChain(message, input)
	} else if receiverChainFromMessage.chainKey().Index > message.Counter {
		// No need to advance the chain
		// Chain already advanced beyond the key for this message
		// Check if the message keys are in the skipped key list.
		for curSkippedIndex := range r.SkippedMessageKeys {
			if message.Counter != r.SkippedMessageKeys[curSkippedIndex].MKey.Index {
				continue
			}

			// Found the key for this message. Check the MAC.
			if cipher, err := aessha2.NewAESSHA2(r.SkippedMessageKeys[curSkippedIndex].MKey.Key, olmKeysKDFInfo); err != nil {
				return nil, err
			} else if verified, err := message.VerifyMACInline(r.SkippedMessageKeys[curSkippedIndex].MKey.Key, cipher, input); err != nil {
				return nil, err
			} else if !verified {
				return nil, fmt.Errorf("decrypt from skipped message keys: %w", olm.ErrBadMAC)
			} else if result, err := cipher.Decrypt(message.Ciphertext); err != nil {
				return nil, fmt.Errorf("cipher decrypt: %w", err)
			} else if len(result) != 0 {
				// Remove the key from the skipped keys now that we've
				// decoded the message it corresponds to.
				r.SkippedMessageKeys[curSkippedIndex] = r.SkippedMessageKeys[len(r.SkippedMessageKeys)-1]
				r.SkippedMessageKeys = r.SkippedMessageKeys[:len(r.SkippedMessageKeys)-1]
				return result, nil
			}
		}
		return nil, fmt.Errorf("decrypt: %w", olm.ErrMessageKeyNotFound)
	} else {
		//Advancing the chain is done in this method
		return r.decryptForExistingChain(receiverChainFromMessage, message, input)
	}
}

// advanceRootKey created the next root key and returns the next chainKey
func (r *Ratchet) advanceRootKey(newRatchetKey crypto.Curve25519KeyPair, oldRatchetKey crypto.Curve25519PublicKey) (crypto.Curve25519PublicKey, error) {
	sharedSecret, err := newRatchetKey.SharedSecret(oldRatchetKey)
	if err != nil {
		return nil, err
	}
	derivedSecretsReader := hkdf.New(sha256.New, sharedSecret, r.RootKey, KdfInfo.Ratchet)
	derivedSecrets := make([]byte, 2*sharedKeyLength)
	if _, err := io.ReadFull(derivedSecretsReader, derivedSecrets); err != nil {
		return nil, err
	}
	r.RootKey = derivedSecrets[:sharedKeyLength]
	return derivedSecrets[sharedKeyLength:], nil
}

// createMessageKeys returns the messageKey derived from the chainKey
func (r Ratchet) createMessageKeys(chainKey chainKey) messageKey {
	hash := hmac.New(sha256.New, chainKey.Key)
	hash.Write([]byte{messageKeySeed})
	return messageKey{
		Key:   hash.Sum(nil),
		Index: chainKey.Index,
	}
}

// decryptForExistingChain returns the decrypted message by using the chain. The MAC of the rawMessage is verified.
func (r *Ratchet) decryptForExistingChain(chain *receiverChain, message *message.Message, rawMessage []byte) ([]byte, error) {
	if message.Counter < chain.CKey.Index {
		return nil, fmt.Errorf("decrypt: %w", olm.ErrChainTooHigh)
	}
	// Limit the number of hashes we're prepared to compute
	if message.Counter-chain.CKey.Index > maxMessageGap {
		return nil, fmt.Errorf("decrypt from existing chain: %w", olm.ErrMsgIndexTooHigh)
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
	cipher, err := aessha2.NewAESSHA2(messageKey.Key, olmKeysKDFInfo)
	if err != nil {
		return nil, err
	}
	verified, err := message.VerifyMACInline(messageKey.Key, cipher, rawMessage)
	if err != nil {
		return nil, err
	}
	if !verified {
		return nil, fmt.Errorf("decrypt from existing chain: %w", olm.ErrBadMAC)
	}
	return cipher.Decrypt(message.Ciphertext)
}

// decryptForNewChain returns the decrypted message by creating a new chain and advancing the root key.
func (r *Ratchet) decryptForNewChain(message *message.Message, rawMessage []byte) ([]byte, error) {
	// They shouldn't move to a new chain until we've sent them a message
	// acknowledging the last one
	if !r.SenderChains.IsSet {
		return nil, fmt.Errorf("decrypt for new chain: %w", olm.ErrProtocolViolation)
	}
	// Limit the number of hashes we're prepared to compute
	if message.Counter > maxMessageGap {
		return nil, fmt.Errorf("decrypt for new chain: %w", olm.ErrMsgIndexTooHigh)
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

	return r.decryptForExistingChain(&r.ReceiverChains[0], message, rawMessage)
}

// PickleAsJSON returns a ratchet as a base64 string encrypted using the supplied key. The unencrypted representation of the Account is in JSON format.
func (r Ratchet) PickleAsJSON(key []byte) ([]byte, error) {
	return libolmpickle.PickleAsJSON(r, olmPickleVersion, key)
}

// UnpickleAsJSON updates a ratchet by a base64 encrypted string using the supplied key. The unencrypted representation has to be in JSON format.
func (r *Ratchet) UnpickleAsJSON(pickled, key []byte) error {
	return libolmpickle.UnpickleAsJSON(r, pickled, key, olmPickleVersion)
}

// UnpickleLibOlm unpickles the unencryted value and populates the [Ratchet]
// accordingly.
func (r *Ratchet) UnpickleLibOlm(decoder *libolmpickle.Decoder, includesChainIndex bool) error {
	if err := r.RootKey.UnpickleLibOlm(decoder); err != nil {
		return err
	}
	senderChainsCount, err := decoder.ReadUInt32()
	if err != nil {
		return err
	}

	for i := uint32(0); i < senderChainsCount; i++ {
		if i == 0 {
			// only the first sender key is stored
			err = r.SenderChains.UnpickleLibOlm(decoder)
			r.SenderChains.IsSet = true
		} else {
			// just eat the values
			err = (&senderChain{}).UnpickleLibOlm(decoder)
		}
		if err != nil {
			return err
		}
	}

	receiverChainCount, err := decoder.ReadUInt32()
	if err != nil {
		return err
	}
	r.ReceiverChains = make([]receiverChain, receiverChainCount)
	for i := uint32(0); i < receiverChainCount; i++ {
		if err := r.ReceiverChains[i].UnpickleLibOlm(decoder); err != nil {
			return err
		}
	}

	skippedMessageKeysCount, err := decoder.ReadUInt32()
	if err != nil {
		return err
	}
	r.SkippedMessageKeys = make([]skippedMessageKey, skippedMessageKeysCount)
	for i := uint32(0); i < skippedMessageKeysCount; i++ {
		if err := r.SkippedMessageKeys[i].UnpickleLibOlm(decoder); err != nil {
			return err
		}
	}

	// pickle version 0x80000001 includes a chain index; pickle version 1 does not.
	if includesChainIndex {
		_, err = decoder.ReadUInt32()
		return err
	}
	return nil
}

// PickleLibOlm pickles the ratchet into the encoder.
func (r Ratchet) PickleLibOlm(encoder *libolmpickle.Encoder) {
	r.RootKey.PickleLibOlm(encoder)
	r.SenderChains.PickleLibOlm(encoder)

	// Receiver Chains
	encoder.WriteUInt32(uint32(len(r.ReceiverChains)))
	for _, curChain := range r.ReceiverChains {
		curChain.PickleLibOlm(encoder)
	}

	// Skipped Message Keys
	encoder.WriteUInt32(uint32(len(r.SkippedMessageKeys)))
	for _, curChain := range r.SkippedMessageKeys {
		curChain.PickleLibOlm(encoder)
	}
}
