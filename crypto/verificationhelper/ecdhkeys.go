package verificationhelper

import (
	"crypto/ecdh"
	"encoding/json"
)

type ECDHPrivateKey struct {
	*ecdh.PrivateKey
}

func (e *ECDHPrivateKey) UnmarshalJSON(data []byte) (err error) {
	if len(data) == 0 {
		return nil
	}
	var raw []byte
	err = json.Unmarshal(data, &raw)
	if err != nil {
		return
	}
	if len(raw) == 0 {
		return nil
	}
	e.PrivateKey, err = ecdh.X25519().NewPrivateKey(raw)
	return err
}

func (e ECDHPrivateKey) MarshalJSON() ([]byte, error) {
	if e.PrivateKey == nil {
		return json.Marshal(nil)
	}
	return json.Marshal(e.Bytes())
}

type ECDHPublicKey struct {
	*ecdh.PublicKey
}

func (e *ECDHPublicKey) UnmarshalJSON(data []byte) (err error) {
	if len(data) == 0 {
		return nil
	}
	var raw []byte
	err = json.Unmarshal(data, &raw)
	if err != nil {
		return
	}
	if len(raw) == 0 {
		return nil
	}
	e.PublicKey, err = ecdh.X25519().NewPublicKey(raw)
	return
}

func (e ECDHPublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.Bytes())
}
