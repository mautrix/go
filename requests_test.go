package mautrix

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReqDeleteDevice(t *testing.T) {
	data := []byte(`{"auth":{"type":"m.login.password","password":"foo","identifier":{"type":"m.id.user","user":"@test:matrix.example"}}}`)

	type PasswordFlow struct {
		Type       AuthType       `json:"type"`
		Password   string         `json:"password"`
		Identifier UserIdentifier `json:"identifier"`
	}

	var req ReqDeleteDevice[*PasswordFlow]
	assert.NoError(t, json.Unmarshal(data, &req))
	assert.Equal(t, AuthTypePassword, req.Auth.Type)
	assert.Equal(t, "foo", req.Auth.Password)
	assert.Equal(t, "m.id.user", string(req.Auth.Identifier.Type))
	assert.Equal(t, "@test:matrix.example", req.Auth.Identifier.User)
}
