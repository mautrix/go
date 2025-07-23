// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package verificationhelper_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog/log" // zerolog-allow-global-log
	"github.com/stretchr/testify/require"
	"go.mau.fi/util/random"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/cryptohelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// mockServer is a mock Matrix server that wraps an [httptest.Server] to allow
// testing of the interactive verification process.
type mockServer struct {
	*httptest.Server

	AccessTokenToUserID map[string]id.UserID
	DeviceInbox         map[id.UserID]map[id.DeviceID][]event.Event
	AccountData         map[id.UserID]map[event.Type]json.RawMessage
	DeviceKeys          map[id.UserID]map[id.DeviceID]mautrix.DeviceKeys
	MasterKeys          map[id.UserID]mautrix.CrossSigningKeys
	SelfSigningKeys     map[id.UserID]mautrix.CrossSigningKeys
	UserSigningKeys     map[id.UserID]mautrix.CrossSigningKeys
}

func createMockServer(t *testing.T) *mockServer {
	t.Helper()

	server := mockServer{
		AccessTokenToUserID: map[string]id.UserID{},
		DeviceInbox:         map[id.UserID]map[id.DeviceID][]event.Event{},
		AccountData:         map[id.UserID]map[event.Type]json.RawMessage{},
		DeviceKeys:          map[id.UserID]map[id.DeviceID]mautrix.DeviceKeys{},
		MasterKeys:          map[id.UserID]mautrix.CrossSigningKeys{},
		SelfSigningKeys:     map[id.UserID]mautrix.CrossSigningKeys{},
		UserSigningKeys:     map[id.UserID]mautrix.CrossSigningKeys{},
	}

	router := http.NewServeMux()
	router.HandleFunc("POST /_matrix/client/v3/login", server.postLogin)
	router.HandleFunc("POST /_matrix/client/v3/keys/query", server.postKeysQuery)
	router.HandleFunc("PUT /_matrix/client/v3/sendToDevice/{type}/{txn}", server.putSendToDevice)
	router.HandleFunc("PUT /_matrix/client/v3/user/{userID}/account_data/{type}", server.putAccountData)
	router.HandleFunc("POST /_matrix/client/v3/keys/device_signing/upload", server.postDeviceSigningUpload)
	router.HandleFunc("POST /_matrix/client/v3/keys/signatures/upload", server.emptyResp)
	router.HandleFunc("POST /_matrix/client/v3/keys/upload", server.postKeysUpload)

	server.Server = httptest.NewServer(router)
	return &server
}

func (ms *mockServer) getUserID(r *http.Request) id.UserID {
	authHeader := r.Header.Get("Authorization")
	authHeader = strings.TrimPrefix(authHeader, "Bearer ")
	userID, ok := ms.AccessTokenToUserID[authHeader]
	if !ok {
		panic("no user ID found for access token " + authHeader)
	}
	return userID
}

func (s *mockServer) emptyResp(w http.ResponseWriter, _ *http.Request) {
	w.Write([]byte("{}"))
}

func (s *mockServer) postLogin(w http.ResponseWriter, r *http.Request) {
	var loginReq mautrix.ReqLogin
	json.NewDecoder(r.Body).Decode(&loginReq)

	deviceID := loginReq.DeviceID
	if deviceID == "" {
		deviceID = id.DeviceID(random.String(10))
	}

	accessToken := random.String(30)
	userID := id.UserID(loginReq.Identifier.User)
	s.AccessTokenToUserID[accessToken] = userID

	json.NewEncoder(w).Encode(&mautrix.RespLogin{
		AccessToken: accessToken,
		DeviceID:    deviceID,
		UserID:      userID,
	})
}

func (s *mockServer) putSendToDevice(w http.ResponseWriter, r *http.Request) {
	var req mautrix.ReqSendToDevice
	json.NewDecoder(r.Body).Decode(&req)
	evtType := event.Type{Type: r.PathValue("type"), Class: event.ToDeviceEventType}

	for user, devices := range req.Messages {
		for device, content := range devices {
			if _, ok := s.DeviceInbox[user]; !ok {
				s.DeviceInbox[user] = map[id.DeviceID][]event.Event{}
			}
			content.ParseRaw(evtType)
			s.DeviceInbox[user][device] = append(s.DeviceInbox[user][device], event.Event{
				Sender:  s.getUserID(r),
				Type:    evtType,
				Content: *content,
			})
		}
	}
	s.emptyResp(w, r)
}

func (s *mockServer) putAccountData(w http.ResponseWriter, r *http.Request) {
	userID := id.UserID(r.PathValue("userID"))
	eventType := event.Type{Type: r.PathValue("type"), Class: event.AccountDataEventType}

	jsonData, _ := io.ReadAll(r.Body)
	if _, ok := s.AccountData[userID]; !ok {
		s.AccountData[userID] = map[event.Type]json.RawMessage{}
	}
	s.AccountData[userID][eventType] = json.RawMessage(jsonData)
	s.emptyResp(w, r)
}

func (s *mockServer) postKeysQuery(w http.ResponseWriter, r *http.Request) {
	var req mautrix.ReqQueryKeys
	json.NewDecoder(r.Body).Decode(&req)
	resp := mautrix.RespQueryKeys{
		MasterKeys:      map[id.UserID]mautrix.CrossSigningKeys{},
		UserSigningKeys: map[id.UserID]mautrix.CrossSigningKeys{},
		SelfSigningKeys: map[id.UserID]mautrix.CrossSigningKeys{},
		DeviceKeys:      map[id.UserID]map[id.DeviceID]mautrix.DeviceKeys{},
	}
	for user := range req.DeviceKeys {
		resp.MasterKeys[user] = s.MasterKeys[user]
		resp.UserSigningKeys[user] = s.UserSigningKeys[user]
		resp.SelfSigningKeys[user] = s.SelfSigningKeys[user]
		resp.DeviceKeys[user] = s.DeviceKeys[user]
	}
	json.NewEncoder(w).Encode(&resp)
}

func (s *mockServer) postKeysUpload(w http.ResponseWriter, r *http.Request) {
	var req mautrix.ReqUploadKeys
	json.NewDecoder(r.Body).Decode(&req)

	userID := s.getUserID(r)
	if _, ok := s.DeviceKeys[userID]; !ok {
		s.DeviceKeys[userID] = map[id.DeviceID]mautrix.DeviceKeys{}
	}
	s.DeviceKeys[userID][req.DeviceKeys.DeviceID] = *req.DeviceKeys

	json.NewEncoder(w).Encode(&mautrix.RespUploadKeys{
		OneTimeKeyCounts: mautrix.OTKCount{SignedCurve25519: 50},
	})
}

func (s *mockServer) postDeviceSigningUpload(w http.ResponseWriter, r *http.Request) {
	var req mautrix.UploadCrossSigningKeysReq
	json.NewDecoder(r.Body).Decode(&req)

	userID := s.getUserID(r)
	s.MasterKeys[userID] = req.Master
	s.SelfSigningKeys[userID] = req.SelfSigning
	s.UserSigningKeys[userID] = req.UserSigning

	s.emptyResp(w, r)
}

func (ms *mockServer) Login(t *testing.T, ctx context.Context, userID id.UserID, deviceID id.DeviceID) (*mautrix.Client, crypto.Store) {
	t.Helper()
	client, err := mautrix.NewClient(ms.URL, "", "")
	require.NoError(t, err)
	client.StateStore = mautrix.NewMemoryStateStore()

	_, err = client.Login(ctx, &mautrix.ReqLogin{
		Type: mautrix.AuthTypePassword,
		Identifier: mautrix.UserIdentifier{
			Type: mautrix.IdentifierTypeUser,
			User: userID.String(),
		},
		DeviceID:         deviceID,
		Password:         "password",
		StoreCredentials: true,
	})
	require.NoError(t, err)

	cryptoStore := crypto.NewMemoryStore(nil)
	cryptoHelper, err := cryptohelper.NewCryptoHelper(client, []byte("test"), cryptoStore)
	require.NoError(t, err)
	client.Crypto = cryptoHelper

	err = cryptoHelper.Init(ctx)
	require.NoError(t, err)

	machineLog := log.Logger.With().
		Stringer("my_user_id", userID).
		Stringer("my_device_id", deviceID).
		Logger()
	cryptoHelper.Machine().Log = &machineLog

	err = cryptoHelper.Machine().ShareKeys(ctx, 50)
	require.NoError(t, err)

	return client, cryptoStore
}

func (ms *mockServer) dispatchToDevice(t *testing.T, ctx context.Context, client *mautrix.Client) {
	t.Helper()

	for _, evt := range ms.DeviceInbox[client.UserID][client.DeviceID] {
		client.Syncer.(*mautrix.DefaultSyncer).Dispatch(ctx, &evt)
		ms.DeviceInbox[client.UserID][client.DeviceID] = ms.DeviceInbox[client.UserID][client.DeviceID][1:]
	}
}

func addDeviceID(ctx context.Context, cryptoStore crypto.Store, userID id.UserID, deviceID id.DeviceID) {
	err := cryptoStore.PutDevice(ctx, userID, &id.Device{
		UserID:   userID,
		DeviceID: deviceID,
	})
	if err != nil {
		panic(err)
	}
}
