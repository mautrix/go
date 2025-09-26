// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mockserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	globallog "github.com/rs/zerolog/log" // zerolog-allow-global-log
	"github.com/stretchr/testify/require"
	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/exerrors"
	"go.mau.fi/util/exhttp"
	"go.mau.fi/util/random"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/cryptohelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func mustDecode(r *http.Request, data any) {
	exerrors.PanicIfNotNil(json.NewDecoder(r.Body).Decode(data))
}

type userAndDeviceID struct {
	UserID   id.UserID
	DeviceID id.DeviceID
}

type MockServer struct {
	Router *http.ServeMux
	Server *httptest.Server

	AccessTokenToUserID map[string]userAndDeviceID
	DeviceInbox         map[id.UserID]map[id.DeviceID][]event.Event
	AccountData         map[id.UserID]map[event.Type]json.RawMessage
	DeviceKeys          map[id.UserID]map[id.DeviceID]mautrix.DeviceKeys
	OneTimeKeys         map[id.UserID]map[id.DeviceID]map[id.KeyID]mautrix.OneTimeKey
	MasterKeys          map[id.UserID]mautrix.CrossSigningKeys
	SelfSigningKeys     map[id.UserID]mautrix.CrossSigningKeys
	UserSigningKeys     map[id.UserID]mautrix.CrossSigningKeys

	PopOTKs     bool
	MemoryStore bool
}

func Create(t testing.TB) *MockServer {
	t.Helper()

	server := MockServer{
		AccessTokenToUserID: map[string]userAndDeviceID{},
		DeviceInbox:         map[id.UserID]map[id.DeviceID][]event.Event{},
		AccountData:         map[id.UserID]map[event.Type]json.RawMessage{},
		DeviceKeys:          map[id.UserID]map[id.DeviceID]mautrix.DeviceKeys{},
		OneTimeKeys:         map[id.UserID]map[id.DeviceID]map[id.KeyID]mautrix.OneTimeKey{},
		MasterKeys:          map[id.UserID]mautrix.CrossSigningKeys{},
		SelfSigningKeys:     map[id.UserID]mautrix.CrossSigningKeys{},
		UserSigningKeys:     map[id.UserID]mautrix.CrossSigningKeys{},
		PopOTKs:             true,
		MemoryStore:         true,
	}

	router := http.NewServeMux()
	router.HandleFunc("POST /_matrix/client/v3/login", server.postLogin)
	router.HandleFunc("POST /_matrix/client/v3/keys/query", server.postKeysQuery)
	router.HandleFunc("POST /_matrix/client/v3/keys/claim", server.postKeysClaim)
	router.HandleFunc("PUT /_matrix/client/v3/sendToDevice/{type}/{txn}", server.putSendToDevice)
	router.HandleFunc("PUT /_matrix/client/v3/user/{userID}/account_data/{type}", server.putAccountData)
	router.HandleFunc("POST /_matrix/client/v3/keys/device_signing/upload", server.postDeviceSigningUpload)
	router.HandleFunc("POST /_matrix/client/v3/keys/signatures/upload", server.emptyResp)
	router.HandleFunc("POST /_matrix/client/v3/keys/upload", server.postKeysUpload)
	server.Router = router
	server.Server = httptest.NewServer(router)
	t.Cleanup(server.Server.Close)
	return &server
}

func (ms *MockServer) getUserID(r *http.Request) userAndDeviceID {
	authHeader := r.Header.Get("Authorization")
	authHeader = strings.TrimPrefix(authHeader, "Bearer ")
	userID, ok := ms.AccessTokenToUserID[authHeader]
	if !ok {
		panic("no user ID found for access token " + authHeader)
	}
	return userID
}

func (ms *MockServer) emptyResp(w http.ResponseWriter, _ *http.Request) {
	exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
}

func (ms *MockServer) postLogin(w http.ResponseWriter, r *http.Request) {
	var loginReq mautrix.ReqLogin
	mustDecode(r, &loginReq)

	deviceID := loginReq.DeviceID
	if deviceID == "" {
		deviceID = id.DeviceID(random.String(10))
	}

	accessToken := random.String(30)
	userID := id.UserID(loginReq.Identifier.User)
	ms.AccessTokenToUserID[accessToken] = userAndDeviceID{
		UserID:   userID,
		DeviceID: deviceID,
	}

	exhttp.WriteJSONResponse(w, http.StatusOK, &mautrix.RespLogin{
		AccessToken: accessToken,
		DeviceID:    deviceID,
		UserID:      userID,
	})
}

func (ms *MockServer) putSendToDevice(w http.ResponseWriter, r *http.Request) {
	var req mautrix.ReqSendToDevice
	mustDecode(r, &req)
	evtType := event.Type{Type: r.PathValue("type"), Class: event.ToDeviceEventType}

	for user, devices := range req.Messages {
		for device, content := range devices {
			if _, ok := ms.DeviceInbox[user]; !ok {
				ms.DeviceInbox[user] = map[id.DeviceID][]event.Event{}
			}
			content.ParseRaw(evtType)
			ms.DeviceInbox[user][device] = append(ms.DeviceInbox[user][device], event.Event{
				Sender:  ms.getUserID(r).UserID,
				Type:    evtType,
				Content: *content,
			})
		}
	}
	ms.emptyResp(w, r)
}

func (ms *MockServer) putAccountData(w http.ResponseWriter, r *http.Request) {
	userID := id.UserID(r.PathValue("userID"))
	eventType := event.Type{Type: r.PathValue("type"), Class: event.AccountDataEventType}

	jsonData, _ := io.ReadAll(r.Body)
	if _, ok := ms.AccountData[userID]; !ok {
		ms.AccountData[userID] = map[event.Type]json.RawMessage{}
	}
	ms.AccountData[userID][eventType] = json.RawMessage(jsonData)
	ms.emptyResp(w, r)
}

func (ms *MockServer) postKeysQuery(w http.ResponseWriter, r *http.Request) {
	var req mautrix.ReqQueryKeys
	mustDecode(r, &req)
	resp := mautrix.RespQueryKeys{
		MasterKeys:      map[id.UserID]mautrix.CrossSigningKeys{},
		UserSigningKeys: map[id.UserID]mautrix.CrossSigningKeys{},
		SelfSigningKeys: map[id.UserID]mautrix.CrossSigningKeys{},
		DeviceKeys:      map[id.UserID]map[id.DeviceID]mautrix.DeviceKeys{},
	}
	for user := range req.DeviceKeys {
		resp.MasterKeys[user] = ms.MasterKeys[user]
		resp.UserSigningKeys[user] = ms.UserSigningKeys[user]
		resp.SelfSigningKeys[user] = ms.SelfSigningKeys[user]
		resp.DeviceKeys[user] = ms.DeviceKeys[user]
	}
	exhttp.WriteJSONResponse(w, http.StatusOK, &resp)
}

func (ms *MockServer) postKeysClaim(w http.ResponseWriter, r *http.Request) {
	var req mautrix.ReqClaimKeys
	mustDecode(r, &req)
	resp := mautrix.RespClaimKeys{
		OneTimeKeys: map[id.UserID]map[id.DeviceID]map[id.KeyID]mautrix.OneTimeKey{},
	}
	for user, devices := range req.OneTimeKeys {
		resp.OneTimeKeys[user] = map[id.DeviceID]map[id.KeyID]mautrix.OneTimeKey{}
		for device := range devices {
			keys := ms.OneTimeKeys[user][device]
			for keyID, key := range keys {
				if ms.PopOTKs {
					delete(keys, keyID)
				}
				resp.OneTimeKeys[user][device] = map[id.KeyID]mautrix.OneTimeKey{
					keyID: key,
				}
				break
			}
		}
	}
	exhttp.WriteJSONResponse(w, http.StatusOK, &resp)
}

func (ms *MockServer) postKeysUpload(w http.ResponseWriter, r *http.Request) {
	var req mautrix.ReqUploadKeys
	mustDecode(r, &req)

	uid := ms.getUserID(r)
	userID := uid.UserID
	if _, ok := ms.DeviceKeys[userID]; !ok {
		ms.DeviceKeys[userID] = map[id.DeviceID]mautrix.DeviceKeys{}
	}
	if _, ok := ms.OneTimeKeys[userID]; !ok {
		ms.OneTimeKeys[userID] = map[id.DeviceID]map[id.KeyID]mautrix.OneTimeKey{}
	}

	if req.DeviceKeys != nil {
		ms.DeviceKeys[userID][uid.DeviceID] = *req.DeviceKeys
	}
	otks, ok := ms.OneTimeKeys[userID][uid.DeviceID]
	if !ok {
		otks = map[id.KeyID]mautrix.OneTimeKey{}
		ms.OneTimeKeys[userID][uid.DeviceID] = otks
	}
	if req.OneTimeKeys != nil {
		maps.Copy(otks, req.OneTimeKeys)
	}

	exhttp.WriteJSONResponse(w, http.StatusOK, &mautrix.RespUploadKeys{
		OneTimeKeyCounts: mautrix.OTKCount{SignedCurve25519: len(otks)},
	})
}

func (ms *MockServer) postDeviceSigningUpload(w http.ResponseWriter, r *http.Request) {
	var req mautrix.UploadCrossSigningKeysReq
	mustDecode(r, &req)

	userID := ms.getUserID(r).UserID
	ms.MasterKeys[userID] = req.Master
	ms.SelfSigningKeys[userID] = req.SelfSigning
	ms.UserSigningKeys[userID] = req.UserSigning

	ms.emptyResp(w, r)
}

func (ms *MockServer) Login(t testing.TB, ctx context.Context, userID id.UserID, deviceID id.DeviceID) (*mautrix.Client, crypto.Store) {
	t.Helper()
	if ctx == nil {
		ctx = context.TODO()
	}
	client, err := mautrix.NewClient(ms.Server.URL, "", "")
	require.NoError(t, err)
	client.Client = ms.Server.Client()

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

	var store any
	if ms.MemoryStore {
		store = crypto.NewMemoryStore(nil)
		client.StateStore = mautrix.NewMemoryStateStore()
	} else {
		store, err = dbutil.NewFromConfig("", dbutil.Config{
			PoolConfig: dbutil.PoolConfig{
				Type:         "sqlite3-fk-wal",
				URI:          fmt.Sprintf("file:%s?mode=memory&cache=shared&_txlock=immediate", random.String(10)),
				MaxOpenConns: 5,
				MaxIdleConns: 1,
			},
		}, nil)
		require.NoError(t, err)
	}
	cryptoHelper, err := cryptohelper.NewCryptoHelper(client, []byte("test"), store)
	require.NoError(t, err)
	client.Crypto = cryptoHelper

	err = cryptoHelper.Init(ctx)
	require.NoError(t, err)

	machineLog := globallog.Logger.With().
		Stringer("my_user_id", userID).
		Stringer("my_device_id", deviceID).
		Logger()
	cryptoHelper.Machine().Log = &machineLog

	err = cryptoHelper.Machine().ShareKeys(ctx, 50)
	require.NoError(t, err)

	return client, cryptoHelper.Machine().CryptoStore
}

func (ms *MockServer) DispatchToDevice(t testing.TB, ctx context.Context, client *mautrix.Client) {
	t.Helper()

	for _, evt := range ms.DeviceInbox[client.UserID][client.DeviceID] {
		client.Syncer.(*mautrix.DefaultSyncer).Dispatch(ctx, &evt)
		ms.DeviceInbox[client.UserID][client.DeviceID] = ms.DeviceInbox[client.UserID][client.DeviceID][1:]
	}
}
