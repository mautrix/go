package verificationhelper

import (
	"crypto/ecdh"
	"encoding/json/jsontext"
	"encoding/json/v2"
)

type ECDHPrivateKey struct {
	*ecdh.PrivateKey
}

func (e *ECDHPrivateKey) UnmarshalJSONFrom(dec *jsontext.Decoder) (err error) {
	var raw []byte
	err = json.UnmarshalDecode(dec, &raw)
	if err != nil {
		return
	}
	if len(raw) == 0 {
		return nil
	}
	e.PrivateKey, err = ecdh.X25519().NewPrivateKey(raw)
	return err
}

func (e ECDHPrivateKey) MarshalJSONTo(enc *jsontext.Encoder) error {
	if e.PrivateKey == nil {
		return enc.WriteToken(jsontext.Null)
	}
	return json.MarshalEncode(enc, e.Bytes())
}

type ECDHPublicKey struct {
	*ecdh.PublicKey
}

func (e *ECDHPublicKey) UnmarshalJSONFrom(dec *jsontext.Decoder) (err error) {
	var raw []byte
	err = json.UnmarshalDecode(dec, &raw)
	if err != nil {
		return
	}
	if len(raw) == 0 {
		return nil
	}
	e.PublicKey, err = ecdh.X25519().NewPublicKey(raw)
	return
}

func (e ECDHPublicKey) MarshalJSONTo(enc *jsontext.Encoder) error {
	return json.MarshalEncode(enc, e.Bytes())
}
