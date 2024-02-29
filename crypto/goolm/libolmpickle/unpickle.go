package libolmpickle

import (
	"fmt"

	"github.com/element-hq/mautrix-go/crypto/goolm"
)

func isZeroByteSlice(bytes []byte) bool {
	b := byte(0)
	for _, s := range bytes {
		b |= s
	}
	return b == 0
}

func UnpickleUInt8(value []byte) (uint8, int, error) {
	if len(value) < 1 {
		return 0, 0, fmt.Errorf("unpickle uint8: %w", goolm.ErrValueTooShort)
	}
	return value[0], 1, nil
}

func UnpickleBool(value []byte) (bool, int, error) {
	if len(value) < 1 {
		return false, 0, fmt.Errorf("unpickle bool: %w", goolm.ErrValueTooShort)
	}
	return value[0] != uint8(0x00), 1, nil
}

func UnpickleBytes(value []byte, length int) ([]byte, int, error) {
	if len(value) < length {
		return nil, 0, fmt.Errorf("unpickle bytes: %w", goolm.ErrValueTooShort)
	}
	resp := value[:length]
	if isZeroByteSlice(resp) {
		return nil, length, nil
	}
	return resp, length, nil
}

func UnpickleUInt32(value []byte) (uint32, int, error) {
	if len(value) < 4 {
		return 0, 0, fmt.Errorf("unpickle uint32: %w", goolm.ErrValueTooShort)
	}
	var res uint32
	count := 0
	for i := 3; i >= 0; i-- {
		res |= uint32(value[count]) << (8 * i)
		count++
	}
	return res, 4, nil
}
