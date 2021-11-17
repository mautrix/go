// Copyright (c) 2021 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type MessageSendCheckpointStep string

const (
	StepClient     MessageSendCheckpointStep = "CLIENT"
	StepHomeserver MessageSendCheckpointStep = "HOMESERVER"
	StepBridge     MessageSendCheckpointStep = "BRIDGE"
	StepRemote     MessageSendCheckpointStep = "REMOTE"
	StepCommand    MessageSendCheckpointStep = "COMMAND"
)

type MessageSendCheckpointStatus string

const (
	StatusSuccesss    MessageSendCheckpointStatus = "SUCCESS"
	StatusWillRetry   MessageSendCheckpointStatus = "WILL_RETRY"
	StatusPermFailure MessageSendCheckpointStatus = "PERM_FAILURE"
)

type MessageSendCheckpointReportedBy string

const (
	ReportedByAsmux  MessageSendCheckpointReportedBy = "ASMUX"
	ReportedByBridge MessageSendCheckpointReportedBy = "BRIDGE"
)

type MessageSendCheckpoint struct {
	EventID     id.EventID                      `json:"event_id"`
	RoomID      id.RoomID                       `json:"room_id"`
	Step        MessageSendCheckpointStep       `json:"step"`
	Timestamp   time.Time                       `json:"timestamp"`
	Status      MessageSendCheckpointStatus     `json:"status"`
	EventType   event.Type                      `json:"event_type"`
	ReportedBy  MessageSendCheckpointReportedBy `json:"reported_by"`
	RetryNum    int                             `json:"retry_num"`
	MessageType event.MessageType               `json:"message_type"`
	Info        string                          `json:"info"`
}

func NewMessageSendCheckpoint(eventID id.EventID, roomID id.RoomID, step MessageSendCheckpointStep, status MessageSendCheckpointStatus, eventType event.Type) *MessageSendCheckpoint {
	return &MessageSendCheckpoint{
		EventID:    eventID,
		RoomID:     roomID,
		Step:       step,
		Timestamp:  time.Now(),
		Status:     status,
		EventType:  eventType,
		ReportedBy: ReportedByBridge,
	}
}

func NewErrorMessageSendCheckpoint(eventID id.EventID, roomID id.RoomID, step MessageSendCheckpointStep, eventType event.Type, err error) *MessageSendCheckpoint {
	return &MessageSendCheckpoint{
		EventID:    eventID,
		RoomID:     roomID,
		Step:       step,
		Timestamp:  time.Now(),
		Status:     StatusPermFailure,
		EventType:  eventType,
		ReportedBy: ReportedByBridge,
	}
}

func GetCheckpointTypes() map[event.Type]interface{} {
	return map[event.Type]interface{}{
		event.EventRedaction:   struct{}{},
		event.EventMessage:     struct{}{},
		event.EventEncrypted:   struct{}{},
		event.EventSticker:     struct{}{},
		event.EventReaction:    struct{}{},
		event.CallInvite:       struct{}{},
		event.CallCandidates:   struct{}{},
		event.CallSelectAnswer: struct{}{},
		event.CallAnswer:       struct{}{},
		event.CallHangup:       struct{}{},
		event.CallReject:       struct{}{},
		event.CallNegotiate:    struct{}{},
	}
}

func (cp *MessageSendCheckpoint) Send(endpoint string, asToken string) error {
	return SendCheckpoints(endpoint, asToken, []*MessageSendCheckpoint{cp})
}

type CheckpointsJson struct {
	Checkpoints []*MessageSendCheckpoint `json:"checkpoints"`
}

func SendCheckpoints(endpoint string, asToken string, checkpoints []*MessageSendCheckpoint) error {
	if endpoint == "" {
		return nil
	}

	var body bytes.Buffer
	checkpointsJson := CheckpointsJson{Checkpoints: checkpoints}
	if err := json.NewEncoder(&body).Encode(checkpointsJson); err != nil {
		return fmt.Errorf("failed to encode message send checkpoint JSON: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &body)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+asToken)
	req.Header.Set("User-Agent", mautrix.DefaultUserAgent+" checkpoint sender")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("Failed to send bridge state update: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		respBody, _ := ioutil.ReadAll(resp.Body)
		if respBody != nil {
			respBody = bytes.ReplaceAll(respBody, []byte("\n"), []byte("\\n"))
		}
		return fmt.Errorf("Unexpected status code %d sending bridge state update: %s", resp.StatusCode, respBody)
	}
	return nil
}
