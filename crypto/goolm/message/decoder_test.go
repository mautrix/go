package message

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeLengthInt(t *testing.T) {
	numbers := []uint32{127, 128, 16383, 16384, 32767}
	expected := []int{1, 2, 2, 3, 3}
	for curIndex := range numbers {
		assert.Equal(t, expected[curIndex], encodeVarIntByteLength(numbers[curIndex]))
	}
}

func TestEncodeLengthString(t *testing.T) {
	var strings [][]byte
	var expected []int
	strings = append(strings, []byte("test"))
	expected = append(expected, 1+4)
	strings = append(strings, []byte("this is a long message with a length of 127 so that the varint of the length is just one byte. just needs some padding---------"))
	expected = append(expected, 1+127)
	strings = append(strings, []byte("this is an even longer message with a length between 128 and 16383 so that the varint of the length needs two byte. just needs some padding again ---------"))
	expected = append(expected, 2+155)
	for curIndex := range strings {
		assert.Equal(t, expected[curIndex], encodeVarStringByteLength(strings[curIndex]))
	}
}

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
		assert.Equal(t, expected[curIndex], encodeVarInt(ints[curIndex]))
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
		assert.Equal(t, expected[curIndex], encodeVarString(strings[curIndex]))
	}
}
