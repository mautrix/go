package libolmpickle_test

import (
	"bytes"
	"testing"

	"github.com/element-hq/mautrix-go/crypto/goolm/libolmpickle"
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
		response, readLength, err := libolmpickle.UnpickleUInt32(values[curIndex])
		if err != nil {
			t.Fatal(err)
		}
		if readLength != 4 {
			t.Fatal("read bytes not correct")
		}
		if response != expected[curIndex] {
			t.Fatalf("response not as expected:\n%v\n%v\n", response, expected[curIndex])
		}
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
		response, readLength, err := libolmpickle.UnpickleBool(values[curIndex])
		if err != nil {
			t.Fatal(err)
		}
		if readLength != 1 {
			t.Fatal("read bytes not correct")
		}
		if response != expected[curIndex] {
			t.Fatalf("response not as expected:\n%v\n%v\n", response, expected[curIndex])
		}
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
		response, readLength, err := libolmpickle.UnpickleUInt8(values[curIndex])
		if err != nil {
			t.Fatal(err)
		}
		if readLength != 1 {
			t.Fatal("read bytes not correct")
		}
		if response != expected[curIndex] {
			t.Fatalf("response not as expected:\n%v\n%v\n", response, expected[curIndex])
		}
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
		response, readLength, err := libolmpickle.UnpickleBytes(values[curIndex], 4)
		if err != nil {
			t.Fatal(err)
		}
		if readLength != 4 {
			t.Fatal("read bytes not correct")
		}
		if !bytes.Equal(response, expected[curIndex]) {
			t.Fatalf("response not as expected:\n%v\n%v\n", response, expected[curIndex])
		}
	}
}
