// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/bridgev2/bridgeconfig"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func newTestASIntent(t *testing.T, handler http.Handler) *ASIntent {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	as := appservice.Create()
	as.Registration = &appservice.Registration{SenderLocalpart: "bridge"}
	as.HomeserverDomain = "example.com"
	err := as.SetHomeserverURL(ts.URL)
	require.NoError(t, err)
	intent := as.Intent(id.NewUserID("bridge", "example.com"))
	cfg := &bridgeconfig.Config{}
	cfg.Matrix.SyncDirectChatList = true
	return &ASIntent{
		Matrix:    intent,
		Connector: &Connector{Config: cfg, AS: as},
	}
}

func TestASIntent_MarkAsDM_ExistingDirectChats(t *testing.T) {
	existingUser := id.UserID("@alice:example.com")
	existingRoom := id.RoomID("!old:example.com")
	newUser := id.UserID("@bob:example.com")
	newRoom := id.RoomID("!new:example.com")

	var setCalled bool
	var setBody event.DirectChatsEventContent
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode(event.DirectChatsEventContent{
				existingUser: {existingRoom},
			})
		case http.MethodPut:
			setCalled = true
			json.NewDecoder(r.Body).Decode(&setBody)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{}`))
		}
	})
	as := newTestASIntent(t, handler)

	err := as.MarkAsDM(context.Background(), newRoom, newUser)
	require.NoError(t, err)
	assert.True(t, setCalled)
	assert.Equal(t, []id.RoomID{existingRoom}, setBody[existingUser])
	assert.Equal(t, []id.RoomID{newRoom}, setBody[newUser])
}

func TestASIntent_MarkAsDM_NotFoundCreatesNew(t *testing.T) {
	userID := id.UserID("@bob:example.com")
	roomID := id.RoomID("!dm:example.com")

	var setCalled bool
	var setBody event.DirectChatsEventContent
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"errcode":"M_NOT_FOUND","error":"Account data not found"}`))
		case http.MethodPut:
			setCalled = true
			json.NewDecoder(r.Body).Decode(&setBody)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{}`))
		}
	})
	as := newTestASIntent(t, handler)

	err := as.MarkAsDM(context.Background(), roomID, userID)
	require.NoError(t, err)
	assert.True(t, setCalled)
	assert.Equal(t, event.DirectChatsEventContent{
		userID: {roomID},
	}, setBody)
}

func TestASIntent_MarkAsDM_OtherErrorReturned(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"errcode":"M_UNKNOWN","error":"Internal server error"}`))
	})
	as := newTestASIntent(t, handler)

	err := as.MarkAsDM(context.Background(), "!room:example.com", "@user:example.com")
	assert.Error(t, err)
}

func TestASIntent_MarkAsDM_AlreadyInList(t *testing.T) {
	userID := id.UserID("@bob:example.com")
	roomID := id.RoomID("!dm:example.com")

	var setCalled bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode(event.DirectChatsEventContent{
				userID: {roomID},
			})
		case http.MethodPut:
			setCalled = true
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{}`))
		}
	})
	as := newTestASIntent(t, handler)

	err := as.MarkAsDM(context.Background(), roomID, userID)
	require.NoError(t, err)
	assert.False(t, setCalled, "SetAccountData should not be called when room is already in list")
}

func TestASIntent_MarkAsDM_SyncDirectChatListDisabled(t *testing.T) {
	var called bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	as := newTestASIntent(t, handler)
	as.Connector.Config.Matrix.SyncDirectChatList = false

	err := as.MarkAsDM(context.Background(), "!room:example.com", "@user:example.com")
	require.NoError(t, err)
	assert.False(t, called, "No HTTP calls should be made when SyncDirectChatList is false")
}

func TestASIntent_MarkAsDM_CacheHit(t *testing.T) {
	userID := id.UserID("@bob:example.com")
	roomID := id.RoomID("!dm:example.com")

	var getCalled bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			getCalled = true
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	})
	as := newTestASIntent(t, handler)
	as.directChatsCache = event.DirectChatsEventContent{
		userID: {roomID},
	}

	err := as.MarkAsDM(context.Background(), roomID, userID)
	require.NoError(t, err)
	assert.False(t, getCalled, "GetAccountData should not be called when cache has the entry")
}

func TestASIntent_MarkAsDM_SetFailureRollsBack(t *testing.T) {
	userID := id.UserID("@bob:example.com")
	roomID := id.RoomID("!dm:example.com")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode(event.DirectChatsEventContent{})
		case http.MethodPut:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"errcode":"M_UNKNOWN","error":"failed"}`))
		}
	})
	as := newTestASIntent(t, handler)

	err := as.MarkAsDM(context.Background(), roomID, userID)
	assert.Error(t, err)
	// After a failed set, the cache should have rolled back (user entry removed since it was new)
	as.dmUpdateLock.Lock()
	_, exists := as.directChatsCache[userID]
	as.dmUpdateLock.Unlock()
	assert.False(t, exists, "Failed SetAccountData should roll back the change")
}

func TestASIntent_MarkAsDM_ConcurrentSafe(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode(event.DirectChatsEventContent{})
		case http.MethodPut:
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{}`))
		}
	})
	as := newTestASIntent(t, handler)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			userID := id.UserID("@user:example.com")
			roomID := id.RoomID(id.RoomID("!room:example.com"))
			err := as.MarkAsDM(context.Background(), roomID, userID)
			assert.NoError(t, err)
		}(i)
	}
	wg.Wait()
}
