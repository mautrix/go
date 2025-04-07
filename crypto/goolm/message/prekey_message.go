package message

import (
	"io"

	"maunium.net/go/mautrix/crypto/goolm/crypto"
	"maunium.net/go/mautrix/crypto/olm"
)

const (
	oneTimeKeyIDTag = 0x0A
	baseKeyTag      = 0x12
	identityKeyTag  = 0x1A
	messageTag      = 0x22
)

type PreKeyMessage struct {
	Version     byte                       `json:"version"`
	IdentityKey crypto.Curve25519PublicKey `json:"id_key"`
	BaseKey     crypto.Curve25519PublicKey `json:"base_key"`
	OneTimeKey  crypto.Curve25519PublicKey `json:"one_time_key"`
	Message     []byte                     `json:"message"`
}

// Decodes decodes the input and populates the corresponding fileds.
func (r *PreKeyMessage) Decode(input []byte) (err error) {
	r.Version = 0
	r.IdentityKey = nil
	r.BaseKey = nil
	r.OneTimeKey = nil
	r.Message = nil
	if len(input) == 0 {
		return nil
	}

	decoder := NewDecoder(input)
	r.Version, err = decoder.ReadByte() // first byte is always version
	if err != nil {
		if err == io.EOF {
			return olm.ErrInputToSmall
		}
		return
	}

	for {
		// Read Key
		if curKey, err := decoder.ReadVarInt(); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		} else if (curKey & 0b111) == 0 {
			// The value is of type varint
			if _, err = decoder.ReadVarInt(); err != nil {
				if err == io.EOF {
					return olm.ErrInputToSmall
				}
				return err
			}
		} else if (curKey & 0b111) == 2 {
			// The value is of type string
			if value, err := decoder.ReadVarBytes(); err != nil {
				if err == io.EOF {
					return olm.ErrInputToSmall
				}
				return err
			} else {
				switch curKey {
				case oneTimeKeyIDTag:
					r.OneTimeKey = value
				case baseKeyTag:
					r.BaseKey = value
				case identityKeyTag:
					r.IdentityKey = value
				case messageTag:
					r.Message = value
				}
			}
		}
	}
}

// CheckField verifies the fields. If theirIdentityKey is nil, it is not compared to the key in the message.
func (r *PreKeyMessage) CheckFields(theirIdentityKey *crypto.Curve25519PublicKey) bool {
	ok := true
	ok = ok && (theirIdentityKey != nil || r.IdentityKey != nil)
	if r.IdentityKey != nil {
		ok = ok && (len(r.IdentityKey) == crypto.Curve25519PrivateKeyLength)
	}
	ok = ok && len(r.Message) != 0
	ok = ok && len(r.BaseKey) == crypto.Curve25519PrivateKeyLength
	ok = ok && len(r.OneTimeKey) == crypto.Curve25519PrivateKeyLength
	return ok
}

// Encode encodes the message.
func (r *PreKeyMessage) Encode() ([]byte, error) {
	var encoder Encoder
	encoder.PutByte(r.Version)
	encoder.PutVarInt(oneTimeKeyIDTag)
	encoder.PutVarBytes(r.OneTimeKey)
	encoder.PutVarInt(identityKeyTag)
	encoder.PutVarBytes(r.IdentityKey)
	encoder.PutVarInt(baseKeyTag)
	encoder.PutVarBytes(r.BaseKey)
	encoder.PutVarInt(messageTag)
	encoder.PutVarBytes(r.Message)
	return encoder.Bytes(), nil
}
