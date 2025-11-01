package message

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"maunium.net/go/mautrix/crypto/olm"
)

type Decoder struct {
	*bytes.Buffer
}

func NewDecoder(buf []byte) *Decoder {
	return &Decoder{bytes.NewBuffer(buf)}
}

func (d *Decoder) ReadVarInt() (uint64, error) {
	return binary.ReadUvarint(d)
}

func (d *Decoder) ReadVarBytes() ([]byte, error) {
	if n, err := d.ReadVarInt(); err != nil {
		return nil, err
	} else if n > uint64(d.Len()) {
		return nil, fmt.Errorf("%w: var bytes length says %d, but only %d bytes left", olm.ErrInputToSmall, n, d.Available())
	} else {
		out := make([]byte, n)
		_, err = d.Read(out)
		return out, err
	}
}
