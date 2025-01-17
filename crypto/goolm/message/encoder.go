package message

import "encoding/binary"

type Encoder struct {
	buf []byte
}

func (e *Encoder) Bytes() []byte {
	return e.buf
}

func (e *Encoder) PutByte(val byte) {
	e.buf = append(e.buf, val)
}

func (e *Encoder) PutVarInt(val uint64) {
	e.buf = binary.AppendUvarint(e.buf, val)
}

func (e *Encoder) PutVarBytes(data []byte) {
	e.PutVarInt(uint64(len(data)))
	e.buf = append(e.buf, data...)
}
