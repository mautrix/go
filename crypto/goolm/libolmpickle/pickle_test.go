package libolmpickle_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"maunium.net/go/mautrix/crypto/goolm/libolmpickle"
)

func TestEncoder(t *testing.T) {
	var encoder libolmpickle.Encoder
	encoder.WriteUInt32(4)
	encoder.WriteUInt8(8)
	encoder.WriteBool(false)
	encoder.WriteEmptyBytes(10)
	encoder.WriteBool(true)
	encoder.Write([]byte("test"))
	encoder.WriteUInt32(420_000)
	assert.Equal(t, []byte{
		0x00, 0x00, 0x00, 0x04, // 4
		0x08,                                                       // 8
		0x00,                                                       // false
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ten empty bytes
		0x01,                   //true
		0x74, 0x65, 0x73, 0x74, // "test" (ASCII)
		0x00, 0x06, 0x68, 0xa0, // 420,000
	}, encoder.Bytes())
}

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
	for i, value := range values {
		var encoder libolmpickle.Encoder
		encoder.WriteUInt32(value)
		assert.Equal(t, expected[i], encoder.Bytes())
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
	for i, value := range values {
		var encoder libolmpickle.Encoder
		encoder.WriteBool(value)
		assert.Equal(t, expected[i], encoder.Bytes())
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
	for i, value := range values {
		var encoder libolmpickle.Encoder
		encoder.WriteUInt8(value)
		assert.Equal(t, expected[i], encoder.Bytes())
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
	for i, value := range values {
		var encoder libolmpickle.Encoder
		encoder.Write(value)
		assert.Equal(t, expected[i], encoder.Bytes())
	}
}
