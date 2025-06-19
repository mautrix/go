// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package status

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"reflect"
	"time"

	"github.com/tidwall/sjson"
	"go.mau.fi/util/jsontime"
	"go.mau.fi/util/ptr"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
)

type BridgeStateEvent string
type BridgeStateErrorCode string

type BridgeStateErrorMap map[BridgeStateErrorCode]string

func (bem BridgeStateErrorMap) Update(data BridgeStateErrorMap) {
	for key, value := range data {
		bem[key] = value
	}
}

var BridgeStateHumanErrors = make(BridgeStateErrorMap)

const (
	StateStarting          BridgeStateEvent = "STARTING"
	StateUnconfigured      BridgeStateEvent = "UNCONFIGURED"
	StateRunning           BridgeStateEvent = "RUNNING"
	StateBridgeUnreachable BridgeStateEvent = "BRIDGE_UNREACHABLE"

	StateConnecting          BridgeStateEvent = "CONNECTING"
	StateBackfilling         BridgeStateEvent = "BACKFILLING"
	StateConnected           BridgeStateEvent = "CONNECTED"
	StateTransientDisconnect BridgeStateEvent = "TRANSIENT_DISCONNECT"
	StateBadCredentials      BridgeStateEvent = "BAD_CREDENTIALS"
	StateUnknownError        BridgeStateEvent = "UNKNOWN_ERROR"
	StateLoggedOut           BridgeStateEvent = "LOGGED_OUT"
)

func (e BridgeStateEvent) IsValid() bool {
	switch e {
	case
		StateStarting,
		StateUnconfigured,
		StateRunning,
		StateBridgeUnreachable,
		StateConnecting,
		StateBackfilling,
		StateConnected,
		StateTransientDisconnect,
		StateBadCredentials,
		StateUnknownError,
		StateLoggedOut:
		return true
	default:
		return false
	}
}

type BridgeStateUserAction string

const (
	UserActionOpenNative BridgeStateUserAction = "OPEN_NATIVE"
	UserActionRelogin    BridgeStateUserAction = "RELOGIN"
	UserActionRestart    BridgeStateUserAction = "RESTART"
)

type RemoteProfile struct {
	Phone    string              `json:"phone,omitempty"`
	Email    string              `json:"email,omitempty"`
	Username string              `json:"username,omitempty"`
	Name     string              `json:"name,omitempty"`
	Avatar   id.ContentURIString `json:"avatar,omitempty"`
}

func coalesce[T ~string](a, b T) T {
	if a != "" {
		return a
	}
	return b
}

func (rp *RemoteProfile) Merge(other RemoteProfile) RemoteProfile {
	other.Phone = coalesce(rp.Phone, other.Phone)
	other.Email = coalesce(rp.Email, other.Email)
	other.Username = coalesce(rp.Username, other.Username)
	other.Name = coalesce(rp.Name, other.Name)
	other.Avatar = coalesce(rp.Avatar, other.Avatar)
	return other
}

func (rp *RemoteProfile) IsEmpty() bool {
	return rp == nil || (rp.Phone == "" && rp.Email == "" && rp.Username == "" && rp.Name == "" && rp.Avatar == "")
}

type BridgeState struct {
	StateEvent BridgeStateEvent `json:"state_event"`
	Timestamp  jsontime.Unix    `json:"timestamp"`
	TTL        int              `json:"ttl"`

	Source  string               `json:"source,omitempty"`
	Error   BridgeStateErrorCode `json:"error,omitempty"`
	Message string               `json:"message,omitempty"`

	UserAction BridgeStateUserAction `json:"user_action,omitempty"`

	UserID        id.UserID      `json:"user_id,omitempty"`
	RemoteID      string         `json:"remote_id,omitempty"`
	RemoteName    string         `json:"remote_name,omitempty"`
	RemoteProfile *RemoteProfile `json:"remote_profile,omitempty"`

	Reason string                 `json:"reason,omitempty"`
	Info   map[string]interface{} `json:"info,omitempty"`
}

type GlobalBridgeState struct {
	RemoteStates map[string]BridgeState `json:"remoteState"`
	BridgeState  BridgeState            `json:"bridgeState"`
}

type BridgeStateFiller interface {
	FillBridgeState(BridgeState) BridgeState
}

// Deprecated: use BridgeStateFiller instead
type StandaloneCustomBridgeStateFiller = BridgeStateFiller

func (pong BridgeState) Fill(user BridgeStateFiller) BridgeState {
	if user != nil {
		pong = user.FillBridgeState(pong)
	}

	pong.Timestamp = jsontime.UnixNow()
	pong.Source = "bridge"
	if len(pong.Error) > 0 {
		pong.TTL = 3600
		msg, ok := BridgeStateHumanErrors[pong.Error]
		if ok {
			pong.Message = msg
		}
	} else {
		pong.TTL = 21600
	}
	return pong
}

func (pong *BridgeState) SendHTTP(ctx context.Context, url, token string) error {
	var body []byte
	var err error
	if body, err = json.Marshal(&pong); err != nil {
		return fmt.Errorf("failed to encode bridge state JSON: %w", err)
	}

	if pong.StateEvent == StateBridgeUnreachable {
		body, err = sjson.SetBytes(body, "stateEvent", pong.StateEvent)
		if err != nil {
			return fmt.Errorf("failed to add stateEvent field to bridge_unreachable state")
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to prepare request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", mautrix.DefaultUserAgent+" (bridge state sender)")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		respBody, _ := io.ReadAll(resp.Body)
		if respBody != nil {
			respBody = bytes.ReplaceAll(respBody, []byte("\n"), []byte("\\n"))
		}
		return fmt.Errorf("unexpected status code %d sending bridge state update: %s", resp.StatusCode, respBody)
	}
	return nil
}

func (pong *BridgeState) ShouldDeduplicate(newPong *BridgeState) bool {
	return pong != nil &&
		pong.StateEvent == newPong.StateEvent &&
		pong.RemoteName == newPong.RemoteName &&
		pong.UserAction == newPong.UserAction &&
		ptr.Val(pong.RemoteProfile) == ptr.Val(newPong.RemoteProfile) &&
		pong.Error == newPong.Error &&
		maps.EqualFunc(pong.Info, newPong.Info, reflect.DeepEqual) &&
		pong.Timestamp.Add(time.Duration(pong.TTL)*time.Second).After(time.Now())
}
