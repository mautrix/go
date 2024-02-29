package message

import (
	"github.com/element-hq/mautrix-go/crypto/goolm/crypto"
)

const (
	oneTimeKeyIdTag = 0x0A
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
func (r *PreKeyMessage) Decode(input []byte) error {
	r.Version = 0
	r.IdentityKey = nil
	r.BaseKey = nil
	r.OneTimeKey = nil
	r.Message = nil
	if len(input) == 0 {
		return nil
	}
	//first Byte is always version
	r.Version = input[0]
	curPos := 1
	for curPos < len(input) {
		//Read Key
		curKey, readBytes := decodeVarInt(input[curPos:])
		if err := checkDecodeErr(readBytes); err != nil {
			return err
		}
		curPos += readBytes
		if (curKey & 0b111) == 0 {
			//The value is of type varint
			_, readBytes := decodeVarInt(input[curPos:])
			if err := checkDecodeErr(readBytes); err != nil {
				return err
			}
			curPos += readBytes
		} else if (curKey & 0b111) == 2 {
			//The value is of type string
			value, readBytes := decodeVarString(input[curPos:])
			if err := checkDecodeErr(readBytes); err != nil {
				return err
			}
			curPos += readBytes
			switch curKey {
			case oneTimeKeyIdTag:
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

	return nil
}

// CheckField verifies the fields. If theirIdentityKey is nil, it is not compared to the key in the message.
func (r *PreKeyMessage) CheckFields(theirIdentityKey *crypto.Curve25519PublicKey) bool {
	ok := true
	ok = ok && (theirIdentityKey != nil || r.IdentityKey != nil)
	if r.IdentityKey != nil {
		ok = ok && (len(r.IdentityKey) == crypto.Curve25519KeyLength)
	}
	ok = ok && len(r.Message) != 0
	ok = ok && len(r.BaseKey) == crypto.Curve25519KeyLength
	ok = ok && len(r.OneTimeKey) == crypto.Curve25519KeyLength
	return ok
}

// Encode encodes the message.
func (r *PreKeyMessage) Encode() ([]byte, error) {
	var lengthOfMessage int
	lengthOfMessage += 1 //Version
	lengthOfMessage += encodeVarIntByteLength(oneTimeKeyIdTag) + encodeVarStringByteLength(r.OneTimeKey)
	lengthOfMessage += encodeVarIntByteLength(identityKeyTag) + encodeVarStringByteLength(r.IdentityKey)
	lengthOfMessage += encodeVarIntByteLength(baseKeyTag) + encodeVarStringByteLength(r.BaseKey)
	lengthOfMessage += encodeVarIntByteLength(messageTag) + encodeVarStringByteLength(r.Message)
	out := make([]byte, lengthOfMessage)
	out[0] = r.Version
	curPos := 1
	encodedTag := encodeVarInt(oneTimeKeyIdTag)
	copy(out[curPos:], encodedTag)
	curPos += len(encodedTag)
	encodedValue := encodeVarString(r.OneTimeKey)
	copy(out[curPos:], encodedValue)
	curPos += len(encodedValue)
	encodedTag = encodeVarInt(identityKeyTag)
	copy(out[curPos:], encodedTag)
	curPos += len(encodedTag)
	encodedValue = encodeVarString(r.IdentityKey)
	copy(out[curPos:], encodedValue)
	curPos += len(encodedValue)
	encodedTag = encodeVarInt(baseKeyTag)
	copy(out[curPos:], encodedTag)
	curPos += len(encodedTag)
	encodedValue = encodeVarString(r.BaseKey)
	copy(out[curPos:], encodedValue)
	curPos += len(encodedValue)
	encodedTag = encodeVarInt(messageTag)
	copy(out[curPos:], encodedTag)
	curPos += len(encodedTag)
	encodedValue = encodeVarString(r.Message)
	copy(out[curPos:], encodedValue)
	return out, nil
}
