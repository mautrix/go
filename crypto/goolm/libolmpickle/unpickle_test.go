package libolmpickle_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"maunium.net/go/mautrix/crypto/goolm/libolmpickle"
)

func TestUnpickleUInt32(t *testing.T) {
	expected := []uint32{
		0xffffffff,
		0x00ff00ff,
		0xf0000000,
	}
	values := [][]byte{
		{0xff, 0xff, 0xff, 0xff},
		{0x00, 0xff, 0x00, 0xff},
		{0xf0, 0x00, 0x00, 0x00},
	}
	for curIndex := range values {
		decoder := libolmpickle.NewDecoder(values[curIndex])
		response, err := decoder.ReadUInt32()
		assert.NoError(t, err)
		assert.Equal(t, expected[curIndex], response)
	}
}

func TestUnpickleBool(t *testing.T) {
	expected := []bool{
		true,
		false,
		true,
	}
	values := [][]byte{
		{0x01},
		{0x00},
		{0x02},
	}
	for curIndex := range values {
		decoder := libolmpickle.NewDecoder(values[curIndex])
		response, err := decoder.ReadBool()
		assert.NoError(t, err)
		assert.Equal(t, expected[curIndex], response)
	}
}

func TestUnpickleUInt8(t *testing.T) {
	expected := []uint8{
		0xff,
		0x1a,
	}
	values := [][]byte{
		{0xff},
		{0x1a},
	}
	for curIndex := range values {
		decoder := libolmpickle.NewDecoder(values[curIndex])
		response, err := decoder.ReadUInt8()
		assert.NoError(t, err)
		assert.Equal(t, expected[curIndex], response)
	}
}

func TestUnpickleBytes(t *testing.T) {
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
		decoder := libolmpickle.NewDecoder(values[curIndex])
		response, err := decoder.ReadBytes(4)
		assert.NoError(t, err)
		assert.Equal(t, expected[curIndex], response)
	}
}
