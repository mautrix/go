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
func (s *Session) PasswordLogin(user, password string) error {
	return s.login(map[string]string{
		"type":     LoginPassword,
		"user":     user,
		"password": password,
	})
}

// TokenLogin tries to log in with username and auth token
func (s *Session) TokenLogin(user, token string) error {
	s.MatrixID = user
	s.AccessToken = token
	return nil
	/*return s.login(map[string]string{
		"type":   LoginToken,
		"user":   user,
		"token":  token,
		"txn_id": GenerateNonce(),
	})*/
}

// DummyLogin tries to log in without authentication
func (s *Session) DummyLogin() error {
	return s.login(map[string]string{"type": LoginDummy})
}

func (s *Session) login(payload interface{}) error {
	creq := s.NewJSONRequest(payload, "/login").POST()
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

	s.AccessToken = dat.AccessToken
	s.MatrixID = dat.UserID

	return nil
}
