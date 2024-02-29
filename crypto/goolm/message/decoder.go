package message

import (
	"encoding/binary"

	"github.com/element-hq/mautrix-go/crypto/goolm"
)

// checkDecodeErr checks if there was an error during decode.
func checkDecodeErr(readBytes int) error {
	if readBytes == 0 {
		//end reached
		return goolm.ErrInputToSmall
	}
	if readBytes < 0 {
		return goolm.ErrOverflow
	}
	return nil
}

// decodeVarInt decodes a single big-endian encoded varint.
func decodeVarInt(input []byte) (uint32, int) {
	value, readBytes := binary.Uvarint(input)
	return uint32(value), readBytes
}

// decodeVarString decodes the length of the string (varint) and returns the actual string
func decodeVarString(input []byte) ([]byte, int) {
	stringLen, readBytes := decodeVarInt(input)
	if readBytes <= 0 {
		return nil, readBytes
	}
	input = input[readBytes:]
	value := input[:stringLen]
	readBytes += int(stringLen)
	return value, readBytes
}

// encodeVarIntByteLength returns the number of bytes needed to encode the uint32.
func encodeVarIntByteLength(input uint32) int {
	result := 1
	for input >= 128 {
		result++
		input >>= 7
	}
	return result
}

// encodeVarStringByteLength returns the number of bytes needed to encode the input.
func encodeVarStringByteLength(input []byte) int {
	result := encodeVarIntByteLength(uint32(len(input)))
	result += len(input)
	return result
}

// encodeVarInt encodes a single uint32
func encodeVarInt(input uint32) []byte {
	out := make([]byte, encodeVarIntByteLength(input))
	binary.PutUvarint(out, uint64(input))
	return out
}

// encodeVarString encodes the length of the input (varint) and appends the actual input
func encodeVarString(input []byte) []byte {
	out := make([]byte, encodeVarStringByteLength(input))
	length := encodeVarInt(uint32(len(input)))
	copy(out, length)
	copy(out[len(length):], input)
	return out
}
