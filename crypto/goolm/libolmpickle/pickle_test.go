package libolmpickle_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"maunium.net/go/mautrix/crypto/goolm/libolmpickle"
)

func TestPickleUInt32(t *testing.T) {
	values := []uint32{
		0xffffffff,
		0x00ff00ff,
		0xf0000000,
		0xf00f0000,
	}
	expected := [][]byte{
		{0xff, 0xff, 0xff, 0xff},
		{0x00, 0xff, 0x00, 0xff},
		{0xf0, 0x00, 0x00, 0x00},
		{0xf0, 0x0f, 0x00, 0x00},
	}
	for curIndex := range values {
		response := make([]byte, 4)
		resPLen := libolmpickle.PickleUInt32(values[curIndex], response)
		assert.Equal(t, libolmpickle.PickleUInt32Length, resPLen)
		assert.Equal(t, expected[curIndex], response)
	}
}

func TestPickleBool(t *testing.T) {
	values := []bool{
		true,
		false,
	}
	expected := [][]byte{
		{0x01},
		{0x00},
	}
	for curIndex := range values {
		response := make([]byte, 1)
		resPLen := libolmpickle.PickleBool(values[curIndex], response)
		assert.Equal(t, libolmpickle.PickleBoolLength, resPLen)
		assert.Equal(t, expected[curIndex], response)
	}
}

func TestPickleUInt8(t *testing.T) {
	values := []uint8{
		0xff,
		0x1a,
	}
	expected := [][]byte{
		{0xff},
		{0x1a},
	}
	for curIndex := range values {
		response := make([]byte, 1)
		resPLen := libolmpickle.PickleUInt8(values[curIndex], response)
		assert.Equal(t, libolmpickle.PickleUInt8Length, resPLen)
		assert.Equal(t, expected[curIndex], response)
	}
}

func TestPickleBytes(t *testing.T) {
	values := [][]byte{
		{0xff, 0xff, 0xff, 0xff},
		{0x00, 0xff, 0x00, 0xff},
		{0xf0, 0x00, 0x00, 0x00},
	}
	expected := [][]byte{
		{0xff, 0xff, 0xff, 0xff},
		{0x00, 0xff, 0x00, 0xff},
		{0xf0, 0x00, 0x00, 0x00},
	}
	for curIndex := range values {
		response := make([]byte, len(values[curIndex]))
		resPLen := libolmpickle.PickleBytes(values[curIndex], response)
		assert.Equal(t, libolmpickle.PickleBytesLen(values[curIndex]), resPLen)
		assert.Equal(t, expected[curIndex], response)
	}
}
