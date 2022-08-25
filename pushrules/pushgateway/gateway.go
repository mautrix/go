// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package pushgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/pushrules"
)

type NotificationCounts struct {
	MissedCalls int `json:"missed_calls,omitempty"`
	Unread      int `json:"unread,omitempty"`
}

type PushPriority string

const (
	PushPriorityHigh PushPriority = "high"
	PushPriorityLow  PushPriority = "low"
)

type BaseDevice struct {
	AppID     string         `json:"app_id"`
	PushKey   string         `json:"push_key"`
	PushKeyTS int64          `json:"push_key_ts,omitempty"`
	Data      map[string]any `json:"data,omitempty"`
}

type PushKey struct {
	BaseDevice
	URL string `json:"url"`
}

type Device struct {
	BaseDevice
	Tweaks map[pushrules.PushActionTweak]any `json:"tweaks,omitempty"`
}

type PushNotification struct {
	Devices []Device `json:"devices"`

	Counts *NotificationCounts `json:"counts,omitempty"`

	EventID           id.EventID      `json:"event_id,omitempty"`
	Priority          PushPriority    `json:"prio,omitempty"`
	RoomAlias         id.RoomAlias    `json:"room_alias,omitempty"`
	RoomID            id.RoomID       `json:"room_id,omitempty"`
	RoomName          string          `json:"room_name,omitempty"`
	Sender            id.UserID       `json:"sender,omitempty"`
	SenderDisplayName string          `json:"sender_display_name,omitempty"`
	Type              string          `json:"type,omitempty"`
	Content           json.RawMessage `json:"content,omitempty"`
	UserIsTarget      bool            `json:"user_is_target,omitempty"`

	// TODO add com.beeper.ttl field and update Sygnal to read that field
}

func (pk *PushKey) Push(ctx context.Context, data *PushNotification) error {
	data.Devices = []Device{{BaseDevice: pk.BaseDevice}}
	return data.Push(ctx, pk.URL)
}

type reqPush struct {
	Notification *PushNotification `json:"notification"`
}

func (pn *PushNotification) Push(ctx context.Context, url string) error {
	payload, err := json.Marshal(&reqPush{Notification: pn})
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to prepare push request: %w", err)
	}
	req.Header.Set("User-Agent", mautrix.DefaultUserAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send push request: %w", err)
	} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, bytes.ReplaceAll(body, []byte("\n"), []byte("\\n")))
	}
	return nil
}
