// Copyright (c) 2021 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package id_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/element-hq/mautrix-go/id"
)

func TestUserID_Parse(t *testing.T) {
	const inputUserID = "@s p a c e:maunium.net"
	parsedLocalpart, parsedServerName, err := id.UserID(inputUserID).Parse()
	assert.NoError(t, err)
	assert.Equal(t, "s p a c e", parsedLocalpart)
	assert.Equal(t, "maunium.net", parsedServerName)
}

func TestUserID_Parse_Empty(t *testing.T) {
	const inputUserID = "@:ponies.im"
	parsedLocalpart, parsedServerName, err := id.UserID(inputUserID).Parse()
	assert.NoError(t, err)
	assert.Equal(t, "", parsedLocalpart)
	assert.Equal(t, "ponies.im", parsedServerName)
}

func TestUserID_Parse_Invalid(t *testing.T) {
	const inputUserID = "hello world"
	_, _, err := id.UserID(inputUserID).Parse()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, id.ErrInvalidUserID))
}

func TestUserID_ParseAndValidate_Invalid(t *testing.T) {
	const inputUserID = "@s p a c e:maunium.net"
	_, _, err := id.UserID(inputUserID).ParseAndValidate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, id.ErrNoncompliantLocalpart))
}

func TestUserID_ParseAndValidate_Empty(t *testing.T) {
	const inputUserID = "@:ponies.im"
	_, _, err := id.UserID(inputUserID).ParseAndValidate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, id.ErrEmptyLocalpart))
}

func TestUserID_ParseAndValidate_Long(t *testing.T) {
	const inputUserID = "@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:example.com"
	_, _, err := id.UserID(inputUserID).ParseAndValidate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, id.ErrUserIDTooLong))
}

func TestUserID_ParseAndValidate_NotLong(t *testing.T) {
	const inputUserID = "@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:example.com"
	_, _, err := id.UserID(inputUserID).ParseAndValidate()
	assert.NoError(t, err)
}

func TestUserIDEncoding(t *testing.T) {
	const inputLocalpart = "This local+part contains IlLeGaL chäracters 🚨"
	const encodedLocalpart = "_this=20local+part=20contains=20_il_le_ga_l=20ch=c3=a4racters=20=f0=9f=9a=a8"
	const inputServerName = "example.com"
	userID := id.NewEncodedUserID(inputLocalpart, inputServerName)
	parsedLocalpart, parsedServerName, err := userID.ParseAndValidate()
	assert.NoError(t, err)
	assert.Equal(t, encodedLocalpart, parsedLocalpart)
	assert.Equal(t, inputServerName, parsedServerName)
	decodedLocalpart, decodedServerName, err := userID.ParseAndDecode()
	assert.NoError(t, err)
	assert.Equal(t, inputLocalpart, decodedLocalpart)
	assert.Equal(t, inputServerName, decodedServerName)
}

func TestUserID_URI(t *testing.T) {
	userID := id.NewUserID("hello", "example.com")
	assert.Equal(t, userID.URI().String(), "matrix:u/hello:example.com")
}
