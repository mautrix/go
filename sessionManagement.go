package goMatrix

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

type loginInfo struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	HomeServer   string `json:"home_server"`
	UserID       string `json:"user_id"`
	Error        string `json:"error"`
}

// Login .
func (session *Session) Login(user, password string) error {
	resp, err := jsonClient(session.HomeServer+"/_matrix/client/r0/login",
		[]byte("{\"type\": \"m.login.password\", \"user\":\""+user+"\", \"password\": \""+password+"\"}"))
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

func jsonClient(url string, jsonStr []byte) (io.ReadCloser, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp.Body, nil
}
