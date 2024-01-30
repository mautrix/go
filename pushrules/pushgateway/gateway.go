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

	"github.com/element-hq/mautrix-go"
	"github.com/element-hq/mautrix-go/id"
	"github.com/element-hq/mautrix-go/pushrules"
)

type NotificationCounts struct {
	MissedCalls int `json:"missed_calls,omitempty"`
	Unread      int `json:"unread,omitempty"`

	BeeperServerType string `json:"com.beeper.server_type,omitempty"`
	BeeperAsOfToken  string `json:"com.beeper.as_of_token,omitempty"`
}

type PushPriority string

const (
	PushPriorityHigh PushPriority = "high"
	PushPriorityLow  PushPriority = "low"
)

type PushFormat string

const (
	PushFormatDefault     PushFormat = ""
	PushFormatEventIDOnly PushFormat = "event_id_only"
)

type PusherData map[string]any

func (pd PusherData) Format() PushFormat {
	val, _ := pd["format"].(string)
	return PushFormat(val)
}

func (pd PusherData) URL() string {
	val, _ := pd["url"].(string)
	return val
}

// ConvertToNotificationData returns a copy of the map with the url and format fields removed.
func (pd PusherData) ConvertToNotificationData() PusherData {
	pdCopy := make(PusherData, len(pd)-2)
	for key, value := range pd {
		if key != "format" && key != "url" {
			pdCopy[key] = value
		}
	}
	return pdCopy
}

type PusherKind string

const (
	PusherKindHTTP  PusherKind = "http"
	PusherKindEmail PusherKind = "email"
)

type PusherAppID string

const (
	PusherAppEmail PusherAppID = "m.email"
)

type Pusher struct {
	AppDisplayName    string      `json:"app_display_name"`
	AppID             PusherAppID `json:"app_id"`
	Data              PusherData  `json:"data"`
	DeviceDisplayName string      `json:"device_display_name"`
	Kind              *PusherKind `json:"kind"`
	Language          string      `json:"lang"`
	ProfileTag        string      `json:"profile_tag,omitempty"`
	PushKey           string      `json:"pushkey"`
}

type RespPushers struct {
	Pushers []Pusher `json:"pushers"`
}

type BaseDevice struct {
	AppID     PusherAppID `json:"app_id"`
	PushKey   string      `json:"pushkey"`
	PushKeyTS int64       `json:"pushkey_ts,omitempty"`
	Data      PusherData  `json:"data,omitempty"`
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

	BeeperTTL                 *int      `json:"com.beeper.ttl,omitempty"`
	BeeperUserID              id.UserID `json:"com.beeper.user_id,omitempty"`
	BeeperLastFullyReadRoomID id.RoomID `json:"com.beeper.last_fully_read_room_id,omitempty"`
}

func (pk *PushKey) Push(ctx context.Context, data *PushNotification) error {
	data.Devices = []Device{{BaseDevice: pk.BaseDevice}}
	return data.Push(ctx, pk.URL)
}

type ReqPush struct {
	Notification *PushNotification `json:"notification"`
}

type RespPush struct {
	Rejected []string `json:"rejected"`
}

var ErrPushRejected error = &RespPush{}

func (rp *RespPush) Error() string {
	return fmt.Sprintf("push gateway rejected keys: %v", rp.Rejected)
}

func (rp *RespPush) Is(other error) bool {
	// Allow using errors.Is(err, ErrPushRejected) as a generic type check
	// without caring about the actual rejected keys.
	if other == ErrPushRejected {
		return true
	}
	otherRespPush, ok := other.(*RespPush)
	if !ok || len(otherRespPush.Rejected) != len(rp.Rejected) {
		return false
	}
	for i, key := range otherRespPush.Rejected {
		if key != rp.Rejected[i] {
			return false
		}
	}
	return true
}

func (pn *PushNotification) Push(ctx context.Context, url string) error {
	payload, err := json.Marshal(&ReqPush{Notification: pn})
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to prepare push request: %w", err)
	}
	req.Header.Set("User-Agent", mautrix.DefaultUserAgent+" (notification pusher)")
	req.Header.Set("Content-Type", "application/json")
	var respData RespPush
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send push request: %w", err)
	} else if body, err := io.ReadAll(resp.Body); err != nil {
		return fmt.Errorf("failed to read push response body (status %d): %v", resp.StatusCode, err)
	} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, bytes.ReplaceAll(body, []byte("\n"), []byte("\\n")))
	} else if err = json.Unmarshal(body, &respData); err != nil {
		return fmt.Errorf("unexpected non-JSON body in push response (status %d): %s", resp.StatusCode, bytes.ReplaceAll(body, []byte("\n"), []byte("\\n")))
	} else if len(respData.Rejected) > 0 {
		return &respData
	}
	return nil
}
