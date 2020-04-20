// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package crypto

import (
	"encoding/gob"
	"os"
	"path/filepath"
	"strings"
)

type Store interface {
	SaveAccount(*OlmAccount) error
	LoadAccount() (*OlmAccount, error)

	SaveSessions(string, []*OlmSession) error
	LoadSessions(string) ([]*OlmSession, error)
}

type GobStore struct {
	Path string
}

func (gs *GobStore) LoadAccount() (*OlmAccount, error) {
	file, err := os.Open(filepath.Join(gs.Path, "account.gob"))
	if err != nil {
		if os.IsNotExist(err) {
			err = nil
		}
		return nil, err
	}
	dec := gob.NewDecoder(file)
	var account OlmAccount
	err = dec.Decode(&account)
	_ = file.Close()
	return &account, err
}

func (gs *GobStore) SaveAccount(account *OlmAccount) error {
	file, err := os.OpenFile(filepath.Join(gs.Path, "account.gob"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	err = gob.NewEncoder(file).Encode(account)
	_ = file.Close()
	return err
}

func pathSafe(val string) string {
	return strings.ReplaceAll(val, "/", "-")
}

func (gs *GobStore) LoadSessions(senderKey string) ([]*OlmSession, error) {
	file, err := os.Open(filepath.Join(gs.Path, "sessions", pathSafe(senderKey) + ".gob"))
	if err != nil {
		if os.IsNotExist(err) {
			return []*OlmSession{}, nil
		}
		return nil, err
	}
	dec := gob.NewDecoder(file)
	var sessions []*OlmSession
	err = dec.Decode(&sessions)
	_ = file.Close()
	return sessions, err
}

func (gs *GobStore) SaveSessions(senderKey string, sessions []*OlmSession) error {
	file, err := os.OpenFile(filepath.Join(gs.Path, "sessions", pathSafe(senderKey) + ".gob"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	err = gob.NewEncoder(file).Encode(sessions)
	_ = file.Close()
	return err
}
