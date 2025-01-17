package message_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"maunium.net/go/mautrix/crypto/goolm/message"
)

func TestEncodeInt(t *testing.T) {
	var ints []uint32
	var expected [][]byte
	ints = append(ints, 7)
	expected = append(expected, []byte{0b00000111})
	ints = append(ints, 127)
	expected = append(expected, []byte{0b01111111})
	ints = append(ints, 128)
	expected = append(expected, []byte{0b10000000, 0b00000001})
	ints = append(ints, 16383)
	expected = append(expected, []byte{0b11111111, 0b01111111})
	for curIndex := range ints {
		var encoder message.Encoder
		encoder.PutVarInt(uint64(ints[curIndex]))
		assert.Equal(t, expected[curIndex], encoder.Bytes())
	}
}

func TestEncodeString(t *testing.T) {
	var strings [][]byte
	var expected [][]byte
	curTest := []byte("test")
	strings = append(strings, curTest)
	res := []byte{
		0b00000100, //varint length of string
	}
	res = append(res, curTest...) //Add string itself
	expected = append(expected, res)
	curTest = []byte("this is a long message with a length of 127 so that the varint of the length is just one byte. just needs some padding---------")
	strings = append(strings, curTest)
	res = []byte{
		0b01111111, //varint length of string
	}
	res = append(res, curTest...) //Add string itself
	expected = append(expected, res)
	curTest = []byte("this is an even longer message with a length between 128 and 16383 so that the varint of the length needs two byte. just needs some padding again ---------")
	strings = append(strings, curTest)
	res = []byte{
		0b10011011, //varint length of string
		0b00000001, //varint length of string
	}
	res = append(res, curTest...) //Add string itself
	expected = append(expected, res)
	for curIndex := range strings {
		var encoder message.Encoder
		encoder.PutVarBytes(strings[curIndex])
		assert.Equal(t, expected[curIndex], encoder.Bytes())
	}
}
