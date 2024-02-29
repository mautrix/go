package libolmpickle_test

import (
	"bytes"
	"testing"

	"github.com/element-hq/mautrix-go/crypto/goolm/libolmpickle"
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
		if resPLen != libolmpickle.PickleUInt32Len(values[curIndex]) {
			t.Fatal("written bytes not correct")
		}
		if !bytes.Equal(response, expected[curIndex]) {
			t.Fatalf("response not as expected:\n%v\n%v\n", response, expected[curIndex])
		}
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
		if resPLen != libolmpickle.PickleBoolLen(values[curIndex]) {
			t.Fatal("written bytes not correct")
		}
		if !bytes.Equal(response, expected[curIndex]) {
			t.Fatalf("response not as expected:\n%v\n%v\n", response, expected[curIndex])
		}
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
		if resPLen != libolmpickle.PickleUInt8Len(values[curIndex]) {
			t.Fatal("written bytes not correct")
		}
		if !bytes.Equal(response, expected[curIndex]) {
			t.Fatalf("response not as expected:\n%v\n%v\n", response, expected[curIndex])
		}
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
		if resPLen != libolmpickle.PickleBytesLen(values[curIndex]) {
			t.Fatal("written bytes not correct")
		}
		if !bytes.Equal(response, expected[curIndex]) {
			t.Fatalf("response not as expected:\n%v\n%v\n", response, expected[curIndex])
		}
	}
}
