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
func (session *Session) PasswordLogin(user, password string) error {
	return session.login(fmt.Sprintf(
		"{\"type\": \"%s\", \"user\": \"%s\", \"password\": \"%s\"}",
		LoginPassword, user, strings.Replace(password, "\"", "\\\"", -1),
	))
}

// TokenLogin tries to log in with username and auth token
func (session *Session) TokenLogin(user, token string) error {
	return session.login(fmt.Sprintf(
		"{\"type\": \"%s\", \"user\": \"%s\", \"token\": \"%s\", \"txn_id\": \"%s\"}",
		LoginToken, user, token, GenerateNonce(),
	))
}

// DummyLogin tries to log in without authentication
func (session *Session) DummyLogin() error {
	return session.login(fmt.Sprintf("{\"type\": \"%s\"}", LoginDummy))
}

func (session *Session) login(payload string) error {
	resp, err := JSONPOST(session.GetURL("/login"), payload)
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

	session.AccessToken = dat.AccessToken

	return nil
}
