package mautrix

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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
	return s.login(fmt.Sprintf(
		"{\"type\": \"%s\", \"user\": \"%s\", \"password\": \"%s\"}",
		LoginPassword, user, strings.Replace(password, "\"", "\\\"", -1),
	))
}

// TokenLogin tries to log in with username and auth token
func (s *Session) TokenLogin(user, token string) error {
	return s.login(fmt.Sprintf(
		"{\"type\": \"%s\", \"user\": \"%s\", \"token\": \"%s\", \"txn_id\": \"%s\"}",
		LoginToken, user, token, GenerateNonce(),
	))
}

// DummyLogin tries to log in without authentication
func (s *Session) DummyLogin() error {
	return s.login(fmt.Sprintf("{\"type\": \"%s\"}", LoginDummy))
}

func (s *Session) login(payload string) error {
	resp, err := JSONPOST(s.GetURL("/login"), payload)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	dat := loginInfo{}
	err = json.NewDecoder(resp.Body).Decode(&dat)
	if err != nil {
		return err
	}

	if dat.Error != "" {
		return fmt.Errorf(dat.Error)
	} else if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	s.AccessToken = dat.AccessToken
	s.MatrixID = dat.UserID

	return nil
}
