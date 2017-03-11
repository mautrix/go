// mautrix - A Matrix client-server library intended for bots.
// Copyright (C) 2017 Tulir Asokan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package mautrix

import (
	"fmt"
)

type loginInfo struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	HomeServer   string `json:"home_server"`
	UserID       string `json:"user_id"`
	Error        string `json:"error"`
}

// PasswordLogin tries to log in with username and password
func (mx *MatrixBot) PasswordLogin(user, password string) error {
	return mx.login(map[string]string{
		"type":     LoginPassword,
		"user":     user,
		"password": password,
	})
}

// SetToken sets the access token to use
func (mx *MatrixBot) SetToken(user, token string) error {
	mx.MatrixID = user
	mx.AccessToken = token
	return nil
}

// DummyLogin tries to log in without authentication
func (mx *MatrixBot) DummyLogin() error {
	return mx.login(map[string]string{"type": LoginDummy})
}

func (mx *MatrixBot) login(payload interface{}) error {
	creq := mx.NewJSONRequest(payload, "/login").POST()
	if !creq.OK() {
		return creq.Error
	}

	var dat loginInfo
	err := creq.JSON(&dat)
	if err != nil {
		return err
	}

	if dat.Error != "" {
		return fmt.Errorf(dat.Error)
	} else if !creq.CheckStatusOK() {
		return fmt.Errorf("HTTP %d", creq.Response.StatusCode)
	}

	mx.AccessToken = dat.AccessToken
	mx.MatrixID = dat.UserID

	return nil
}
