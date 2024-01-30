// Copyright (c) 2021 Sumner Evans
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
	"net/http"
	"time"

	"go.mau.fi/util/jsontime"

	"github.com/element-hq/mautrix-go"
	"github.com/element-hq/mautrix-go/event"
	"github.com/element-hq/mautrix-go/id"
)

type MessageCheckpointStep string

const (
	MsgStepClient     MessageCheckpointStep = "CLIENT"
	MsgStepHomeserver MessageCheckpointStep = "HOMESERVER"
	MsgStepBridge     MessageCheckpointStep = "BRIDGE"
	MsgStepDecrypted  MessageCheckpointStep = "DECRYPTED"
	MsgStepRemote     MessageCheckpointStep = "REMOTE"
	MsgStepCommand    MessageCheckpointStep = "COMMAND"
)

func (mcs MessageCheckpointStep) order() int {
	checkpointOrder := map[MessageCheckpointStep]int{
		MsgStepClient:     0,
		MsgStepHomeserver: 1,
		MsgStepBridge:     2,
		MsgStepDecrypted:  3,
		MsgStepRemote:     4,
		MsgStepCommand:    4,
	}
	if order, ok := checkpointOrder[mcs]; !ok {
		panic(fmt.Sprintf("Unknown checkpoint step %s", mcs))
	} else {
		return order
	}
}

func (mcs MessageCheckpointStep) Before(other MessageCheckpointStep) bool {
	return mcs.order() < other.order()
}

func (mcs MessageCheckpointStep) IsValid() bool {
	switch mcs {
	case MsgStepClient, MsgStepHomeserver, MsgStepBridge, MsgStepDecrypted, MsgStepRemote, MsgStepCommand:
		return true
	}
	return false
}

type MessageCheckpointStatus string

const (
	MsgStatusSuccess        MessageCheckpointStatus = "SUCCESS"
	MsgStatusWillRetry      MessageCheckpointStatus = "WILL_RETRY"
	MsgStatusPermFailure    MessageCheckpointStatus = "PERM_FAILURE"
	MsgStatusUnsupported    MessageCheckpointStatus = "UNSUPPORTED"
	MsgStatusTimeout        MessageCheckpointStatus = "TIMEOUT"
	MsgStatusDelivered      MessageCheckpointStatus = "DELIVERED"
	MsgStatusDeliveryFailed MessageCheckpointStatus = "DELIVERY_FAILED"
)

func (mcs MessageCheckpointStatus) IsValid() bool {
	switch mcs {
	case MsgStatusSuccess, MsgStatusWillRetry, MsgStatusPermFailure, MsgStatusUnsupported, MsgStatusTimeout, MsgStatusDelivered, MsgStatusDeliveryFailed:
		return true
	}
	return false
}

func ReasonToCheckpointStatus(reason event.MessageStatusReason, status event.MessageStatus) MessageCheckpointStatus {
	if status == event.MessageStatusPending {
		return MsgStatusWillRetry
	}
	switch reason {
	case event.MessageStatusUnsupported:
		return MsgStatusUnsupported
	case event.MessageStatusTooOld:
		return MsgStatusTimeout
	default:
		return MsgStatusPermFailure
	}
}

type MessageCheckpointReportedBy string

const (
	MsgReportedByAsmux  MessageCheckpointReportedBy = "ASMUX"
	MsgReportedByBridge MessageCheckpointReportedBy = "BRIDGE"
	MsgReportedByHungry MessageCheckpointReportedBy = "HUNGRYSERV"
)

func (mcrb MessageCheckpointReportedBy) IsValid() bool {
	switch mcrb {
	case MsgReportedByAsmux, MsgReportedByBridge, MsgReportedByHungry:
		return true
	}
	return false
}

type MessageCheckpoint struct {
	EventID     id.EventID                  `json:"event_id"`
	RoomID      id.RoomID                   `json:"room_id"`
	Step        MessageCheckpointStep       `json:"step"`
	Timestamp   jsontime.UnixMilli          `json:"timestamp"`
	Status      MessageCheckpointStatus     `json:"status"`
	EventType   event.Type                  `json:"event_type"`
	ReportedBy  MessageCheckpointReportedBy `json:"reported_by"`
	RetryNum    int                         `json:"retry_num"`
	MessageType event.MessageType           `json:"message_type,omitempty"`
	Info        string                      `json:"info,omitempty"`

	ClientType    string `json:"client_type,omitempty"`
	ClientVersion string `json:"client_version,omitempty"`

	OriginalEventID  id.EventID `json:"original_event_id,omitempty"`
	ManualRetryCount int        `json:"manual_retry_count,omitempty"`
}

var CheckpointTypes = map[event.Type]struct{}{
	event.EventRedaction: {},
	event.EventMessage:   {},
	event.EventEncrypted: {},
	event.EventSticker:   {},
	event.EventReaction:  {},
	//event.CallInvite:       {},
	//event.CallCandidates:   {},
	//event.CallSelectAnswer: {},
	//event.CallAnswer:       {},
	//event.CallHangup:       {},
	//event.CallReject:       {},
	//event.CallNegotiate:    {},
}

func NewMessageCheckpoint(evt *event.Event, step MessageCheckpointStep, status MessageCheckpointStatus, retryNum int) *MessageCheckpoint {
	checkpoint := MessageCheckpoint{
		EventID:    evt.ID,
		RoomID:     evt.RoomID,
		Step:       step,
		Timestamp:  jsontime.UnixMilliNow(),
		Status:     status,
		EventType:  evt.Type,
		ReportedBy: MsgReportedByBridge,
		RetryNum:   retryNum,
	}
	if evt.Type == event.EventMessage {
		checkpoint.MessageType = evt.Content.AsMessage().MsgType
	}
	if retryMeta := evt.Content.AsMessage().MessageSendRetry; retryMeta != nil {
		checkpoint.OriginalEventID = retryMeta.OriginalEventID
		checkpoint.ManualRetryCount = retryMeta.RetryCount
	}
	return &checkpoint
}

type CheckpointsJSON struct {
	Checkpoints []*MessageCheckpoint `json:"checkpoints"`
}

func (cj *CheckpointsJSON) SendHTTP(endpoint string, token string) error {
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(cj); err != nil {
		return fmt.Errorf("failed to encode message checkpoint JSON: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &body)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", mautrix.DefaultUserAgent+" (checkpoint sender)")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return mautrix.HTTPError{
			Request:  req,
			Response: resp,

			WrappedError: err,
			Message:      "failed to send message checkpoint",
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return mautrix.HTTPError{
			Request:  req,
			Response: resp,

			Message: "failed to send message checkpoint",
		}
	}
	return nil
}
