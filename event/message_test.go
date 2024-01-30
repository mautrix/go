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
	"github.com/element-hq/mautrix-go/id"
)

const invalidMessageEvent = `{
	"sender": "@tulir:maunium.net",
	"type": "m.room.message",
	"origin_server_ts": 1587252684192,
	"event_id": "$foo",
	"room_id": "!bar",
	"content": {
		"body": {
			"hmm": false
		}
	}
}`

func TestMessageEventContent__ParseInvalid(t *testing.T) {
	var evt *event.Event
	err := json.Unmarshal([]byte(invalidMessageEvent), &evt)
	assert.Nil(t, err)

	assert.Equal(t, id.UserID("@tulir:maunium.net"), evt.Sender)
	assert.Equal(t, event.EventMessage, evt.Type)
	assert.Equal(t, int64(1587252684192), evt.Timestamp)
	assert.Equal(t, id.EventID("$foo"), evt.ID)
	assert.Equal(t, id.RoomID("!bar"), evt.RoomID)

	err = evt.Content.ParseRaw(evt.Type)
	assert.NotNil(t, err)
}

const messageEvent = `{
	"sender": "@tulir:maunium.net",
	"type": "m.room.message",
	"origin_server_ts": 1587252684192,
	"event_id": "$foo",
	"room_id": "!bar",
	"content": {
		"msgtype": "m.text",
		"body": "* **Hello**, World!",
		"format": "org.matrix.custom.html",
		"formatted_body": "* <strong>Hello</strong>, World!",
		"m.new_content": {
			"msgtype": "m.text",
			"body": "**Hello**, World!",
			"format": "org.matrix.custom.html",
			"formatted_body": "<strong>Hello</strong>, World!"
		}
	}
}`

func TestMessageEventContent__ParseEdit(t *testing.T) {
	var evt *event.Event
	err := json.Unmarshal([]byte(messageEvent), &evt)
	assert.Nil(t, err)

	assert.Equal(t, id.UserID("@tulir:maunium.net"), evt.Sender)
	assert.Equal(t, event.EventMessage, evt.Type)
	assert.Equal(t, int64(1587252684192), evt.Timestamp)
	assert.Equal(t, id.EventID("$foo"), evt.ID)
	assert.Equal(t, id.RoomID("!bar"), evt.RoomID)

	err = evt.Content.ParseRaw(evt.Type)
	require.NoError(t, err)

	assert.IsType(t, &event.MessageEventContent{}, evt.Content.Parsed)
	content := evt.Content.Parsed.(*event.MessageEventContent)
	assert.Equal(t, event.MsgText, content.MsgType)
	assert.Equal(t, event.MsgText, content.NewContent.MsgType)
	assert.Equal(t, "**Hello**, World!", content.NewContent.Body)
	assert.Equal(t, "<strong>Hello</strong>, World!", content.NewContent.FormattedBody)
}

const imageMessageEvent = `{
	"sender": "@tulir:maunium.net",
	"type": "m.room.message",
	"origin_server_ts": 1587252684192,
	"event_id": "$foo",
	"room_id": "!bar",
	"content": {
		"msgtype": "m.image",
		"body": "image.png",
		"url": "mxc://example.com/image",
		"info": {
			"mimetype": "image/png",
			"w": 64,
			"h": 64,
			"size": 12345,
			"thumbnail_url": "mxc://example.com/image_thumb"
		}
	}
}`

func TestMessageEventContent__ParseMedia(t *testing.T) {
	var evt *event.Event
	err := json.Unmarshal([]byte(imageMessageEvent), &evt)
	assert.Nil(t, err)

	assert.Equal(t, id.UserID("@tulir:maunium.net"), evt.Sender)
	assert.Equal(t, event.EventMessage, evt.Type)
	assert.Equal(t, int64(1587252684192), evt.Timestamp)
	assert.Equal(t, id.EventID("$foo"), evt.ID)
	assert.Equal(t, id.RoomID("!bar"), evt.RoomID)

	err = evt.Content.ParseRaw(evt.Type)
	require.NoError(t, err)

	assert.IsType(t, &event.MessageEventContent{}, evt.Content.Parsed)
	content := evt.Content.Parsed.(*event.MessageEventContent)
	assert.Equal(t, event.MsgImage, content.MsgType)
	parsedURL, err := content.URL.Parse()
	assert.Nil(t, err)
	assert.Equal(t, id.ContentURI{Homeserver: "example.com", FileID: "image"}, parsedURL)
	assert.Nil(t, content.NewContent)
	assert.Equal(t, "image/png", content.GetInfo().MimeType)
	assert.EqualValues(t, 64, content.GetInfo().Width)
	assert.EqualValues(t, 64, content.GetInfo().Height)
	assert.EqualValues(t, 12345, content.GetInfo().Size)
}

var parsedMessage = &event.Content{
	Parsed: &event.MessageEventContent{
		MsgType: event.MsgText,
		Body:    "test",
	},
}

const expectedMarshalResult = `{"msgtype":"m.text","body":"test"}`

func TestMessageEventContent__Marshal(t *testing.T) {
	data, err := json.Marshal(parsedMessage)
	assert.Nil(t, err)
	assert.Equal(t, expectedMarshalResult, string(data))
}

var customParsedMessage = &event.Content{
	Raw: map[string]interface{}{
		"net.maunium.custom": "hello world",
	},
	Parsed: &event.MessageEventContent{
		MsgType: event.MsgText,
		Body:    "test",
	},
}

const expectedCustomMarshalResult = `{"body":"test","msgtype":"m.text","net.maunium.custom":"hello world"}`

func TestMessageEventContent__Marshal_Custom(t *testing.T) {
	data, err := json.Marshal(customParsedMessage)
	assert.Nil(t, err)
	assert.Equal(t, expectedCustomMarshalResult, string(data))
}
