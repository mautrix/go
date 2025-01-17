package message

import (
	"bytes"
	"encoding/binary"
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
	} else {
		out := make([]byte, n)
		_, err = d.Read(out)
		return out, err
	}
}
