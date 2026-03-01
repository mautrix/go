// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mautrix_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func TestClient_SendEphemeralEvent_UsesUnstablePathTxnAndTS(t *testing.T) {
	roomID := id.RoomID("!room:example.com")
	evtType := event.Type{Type: "com.example.ephemeral", Class: event.EphemeralEventType}
	txnID := "txn-123"

	var gotPath string
	var gotQueryTS string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQueryTS = r.URL.Query().Get("ts")
		assert.Equal(t, http.MethodPut, r.Method)
		_, _ = w.Write([]byte(`{"event_id":"$evt"}`))
	}))
	defer ts.Close()

	cli, err := mautrix.NewClient(ts.URL, "", "")
	require.NoError(t, err)

	_, err = cli.SendEphemeralEvent(
		context.Background(),
		roomID,
		evtType,
		map[string]any{"foo": "bar"},
		mautrix.ReqSendEvent{TransactionID: txnID, Timestamp: 1234},
	)
	require.NoError(t, err)

	assert.True(t, strings.Contains(gotPath, "/_matrix/client/unstable/com.beeper.ephemeral/rooms/"))
	assert.True(t, strings.HasSuffix(gotPath, "/ephemeral/com.example.ephemeral/"+txnID))
	assert.Equal(t, "1234", gotQueryTS)
}

func TestClient_SendEphemeralEvent_UnsupportedReturnsMUnrecognized(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errcode":"M_UNRECOGNIZED","error":"Unrecognized endpoint"}`))
	}))
	defer ts.Close()

	cli, err := mautrix.NewClient(ts.URL, "", "")
	require.NoError(t, err)

	_, err = cli.SendEphemeralEvent(
		context.Background(),
		id.RoomID("!room:example.com"),
		event.Type{Type: "com.example.ephemeral", Class: event.EphemeralEventType},
		map[string]any{"foo": "bar"},
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, mautrix.MUnrecognized))
}

func TestClient_SendEphemeralEvent_EncryptsInEncryptedRooms(t *testing.T) {
	roomID := id.RoomID("!room:example.com")
	evtType := event.Type{Type: "com.example.ephemeral", Class: event.EphemeralEventType}
	txnID := "txn-encrypted"

	stateStore := mautrix.NewMemoryStateStore()
	err := stateStore.SetEncryptionEvent(context.Background(), roomID, &event.EncryptionEventContent{
		Algorithm: id.AlgorithmMegolmV1,
	})
	require.NoError(t, err)

	fakeCrypto := &fakeCryptoHelper{
		encryptedContent: &event.EncryptedEventContent{
			Algorithm:        id.AlgorithmMegolmV1,
			MegolmCiphertext: []byte("ciphertext"),
		},
	}

	var gotPath string
	var gotBody map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		assert.Equal(t, http.MethodPut, r.Method)
		err := json.NewDecoder(r.Body).Decode(&gotBody)
		require.NoError(t, err)
		_, _ = w.Write([]byte(`{"event_id":"$evt"}`))
	}))
	defer ts.Close()

	cli, err := mautrix.NewClient(ts.URL, "", "")
	require.NoError(t, err)
	cli.StateStore = stateStore
	cli.Crypto = fakeCrypto

	_, err = cli.SendEphemeralEvent(
		context.Background(),
		roomID,
		evtType,
		map[string]any{"foo": "bar"},
		mautrix.ReqSendEvent{TransactionID: txnID},
	)
	require.NoError(t, err)

	assert.True(t, strings.HasSuffix(gotPath, "/ephemeral/m.room.encrypted/"+txnID))
	assert.Equal(t, string(id.AlgorithmMegolmV1), gotBody["algorithm"])
	assert.Equal(t, 1, fakeCrypto.encryptCalls)
	assert.Equal(t, roomID, fakeCrypto.lastRoomID)
	assert.Equal(t, evtType, fakeCrypto.lastEventType)
}

type fakeCryptoHelper struct {
	encryptCalls     int
	lastRoomID       id.RoomID
	lastEventType    event.Type
	lastEncryptInput any
	encryptedContent *event.EncryptedEventContent
}

func (f *fakeCryptoHelper) Encrypt(_ context.Context, roomID id.RoomID, eventType event.Type, content any) (*event.EncryptedEventContent, error) {
	f.encryptCalls++
	f.lastRoomID = roomID
	f.lastEventType = eventType
	f.lastEncryptInput = content
	return f.encryptedContent, nil
}

func (f *fakeCryptoHelper) Decrypt(context.Context, *event.Event) (*event.Event, error) {
	return nil, nil
}

func (f *fakeCryptoHelper) WaitForSession(context.Context, id.RoomID, id.SenderKey, id.SessionID, time.Duration) bool {
	return false
}

func (f *fakeCryptoHelper) RequestSession(context.Context, id.RoomID, id.SenderKey, id.SessionID, id.UserID, id.DeviceID) {
}

func (f *fakeCryptoHelper) Init(context.Context) error {
	return nil
}
