package mautrix

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
		"{\"type\": \"%s\", \"user\":\"%s\", \"password\": \"%s\"}",
		LoginPassword, user, password,
	))
}

// TokenLogin tries to log in with username and auth token
func (session *Session) TokenLogin(user, token string) error {
	return session.login(fmt.Sprintf(
		"{\"type\": \"%s\", \"user\":\"%s\", \"password\": \"%s\", \"txn_id\": \"%s\"}",
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
	defer resp.Close()

	dat := loginInfo{}
	err = json.NewDecoder(resp).Decode(&dat)
	if err != nil {
		return err
	}

	if dat.Error != "" {
		return errors.New(dat.Error)
	}

	session.AccessToken = dat.AccessToken

	return nil
}

// JSONPOST makes a JSON POST request to the given URL with the given body.
func JSONPOST(url, payload string) (io.ReadCloser, error) {
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp.Body, nil
}
