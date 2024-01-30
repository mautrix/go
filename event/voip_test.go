// Copyright (c) 2020 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package event_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/element-hq/mautrix-go/event"
)

const callCandidates = `{
	"type": "m.call.candidates",
	"event_id": "$143273582443PhrSn:example.org",
	"origin_server_ts": 1432735824653,
	"room_id": "!jEsUZKDJdhlrceRyVU:example.org",
	"sender": "@example:example.org",
	"content": {
		"call_id": "12345",
		"candidates": [
			{
				"candidate": "candidate:863018703 1 udp 2122260223 10.9.64.156 43670 typ host generation 0",
				"sdpMLineIndex": 0,
				"sdpMid": "audio"
			}
		],
		"version": 0
	},
	"unsigned": {
		"age": 1234
	}
}`

const callSelectAnswer = `{
	"type": "m.call.select_answer",
	"event_id": "$143273582443PhrSn:example.org",
	"origin_server_ts": 1432735824653,
	"room_id": "!jEsUZKDJdhlrceRyVU:example.org",
	"sender": "@example:example.org",
	"content": {
		"version": 1,
		"call_id": "12345",
		"party_id": "67890",
		"selected_party_id": "111213"
	},
	"unsigned": {
		"age": 1234
	}
}`

const callAnswerStringVersion = `{
	"type": "m.call.answer",
	"event_id": "$143273582443PhrSn:example.org",
	"origin_server_ts": 1432735824653,
	"room_id": "!jEsUZKDJdhlrceRyVU:example.org",
	"sender": "@example:example.org",
	"content": {
		"answer": {
			"sdp": "v=0\r\no=- 6584580628695956864 2 IN IP4 127.0.0.1[...]",
			"type": "answer"
		},
		"call_id": "12345",
		"lifetime": 60000,
		"version": "com.example.call.version"
	},
	"unsigned": {
		"age": 1234
	}
}`

func TestCallCandidatesEventContent_Parse(t *testing.T) {
	var evt *event.Event
	err := json.Unmarshal([]byte(callCandidates), &evt)
	require.NoError(t, err)
	require.Equal(t, evt.Type, event.CallCandidates)
	err = evt.Content.ParseRaw(evt.Type)
	require.NoError(t, err)
	content := evt.Content.AsCallCandidates()
	require.NotNil(t, content)
	assert.Equal(t, event.CallVersion("0"), content.Version)
}

func TestCallSelectAnswerEventContent_Parse(t *testing.T) {
	var evt *event.Event
	err := json.Unmarshal([]byte(callSelectAnswer), &evt)
	require.NoError(t, err)
	require.Equal(t, evt.Type, event.CallSelectAnswer)
	err = evt.Content.ParseRaw(evt.Type)
	require.NoError(t, err)
	content := evt.Content.AsCallSelectAnswer()
	require.NotNil(t, content)
	assert.Equal(t, event.CallVersion("1"), content.Version)
}

func TestCallAnswerContent_Parse(t *testing.T) {
	var evt *event.Event
	err := json.Unmarshal([]byte(callAnswerStringVersion), &evt)
	require.NoError(t, err)
	require.Equal(t, evt.Type, event.CallAnswer)
	err = evt.Content.ParseRaw(evt.Type)
	require.NoError(t, err)
	content := evt.Content.AsCallAnswer()
	require.NotNil(t, content)
	assert.Equal(t, event.CallVersion("com.example.call.version"), content.Version)
}

func TestCallVersion_MarshalJSON(t *testing.T) {
	var version event.CallVersion
	var data []byte
	var err error

	version = "1"
	data, err = json.Marshal(&version)
	assert.NoError(t, err)
	assert.Equal(t, []byte("1"), data)

	version = "0"
	data, err = json.Marshal(&version)
	assert.NoError(t, err)
	assert.Equal(t, []byte("0"), data)

	version = "1234"
	data, err = json.Marshal(&version)
	assert.NoError(t, err)
	assert.Equal(t, []byte("1234"), data)

	version = "com.example.call.version"
	data, err = json.Marshal(&version)
	assert.NoError(t, err)
	assert.Equal(t, []byte(`"com.example.call.version"`), data)
}

func TestCallVersion_UnmarshalJSON(t *testing.T) {
	var version event.CallVersion
	var err error

	err = json.Unmarshal([]byte(`1`), &version)
	assert.NoError(t, err)
	assert.Equal(t, event.CallVersion("1"), version)

	err = json.Unmarshal([]byte(`0`), &version)
	assert.NoError(t, err)
	assert.Equal(t, event.CallVersion("0"), version)

	err = json.Unmarshal([]byte(`1234`), &version)
	assert.NoError(t, err)
	assert.Equal(t, event.CallVersion("1234"), version)

	err = json.Unmarshal([]byte(`"1234"`), &version)
	assert.NoError(t, err)
	assert.Equal(t, event.CallVersion("1234"), version)

	err = json.Unmarshal([]byte(`"com.example.call.version"`), &version)
	assert.NoError(t, err)
	assert.Equal(t, event.CallVersion("com.example.call.version"), version)

	err = json.Unmarshal([]byte(`1.234`), &version)
	assert.Error(t, err)

	err = json.Unmarshal([]byte(`false`), &version)
	assert.Error(t, err)

	err = json.Unmarshal([]byte(`["hmm"]`), &version)
	assert.Error(t, err)

	err = json.Unmarshal([]byte(`{"hmm": true}`), &version)
	assert.Error(t, err)
}
