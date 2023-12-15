package libolmpickle

import (
	"encoding/binary"
)

func PickleUInt8(value uint8, target []byte) int {
	target[0] = value
	return 1
}
func PickleUInt8Len(value uint8) int {
	return 1
}

func PickleBool(value bool, target []byte) int {
	if value {
		target[0] = 0x01
	} else {
		target[0] = 0x00
	}
	return 1
}
func PickleBoolLen(value bool) int {
	return 1
}

func PickleBytes(value, target []byte) int {
	return copy(target, value)
}
func PickleBytesLen(value []byte) int {
	return len(value)
}

func PickleUInt32(value uint32, target []byte) int {
	res := make([]byte, 4) //4 bytes for int32
	binary.BigEndian.PutUint32(res, value)
	return copy(target, res)
}
func PickleUInt32Len(value uint32) int {
	return 4
}
