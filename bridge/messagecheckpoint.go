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
	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
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

type MessageCheckpointStatus string

const (
	MsgStatusSuccess     MessageCheckpointStatus = "SUCCESS"
	MsgStatusWillRetry   MessageCheckpointStatus = "WILL_RETRY"
	MsgStatusPermFailure MessageCheckpointStatus = "PERM_FAILURE"
	MsgStatusUnsupported MessageCheckpointStatus = "UNSUPPORTED"
	MsgStatusTimeout     MessageCheckpointStatus = "TIMEOUT"
)

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
)

type MessageCheckpoint struct {
	EventID     id.EventID                  `json:"event_id"`
	RoomID      id.RoomID                   `json:"room_id"`
	Step        MessageCheckpointStep       `json:"step"`
	Timestamp   int64                       `json:"timestamp"`
	Status      MessageCheckpointStatus     `json:"status"`
	EventType   event.Type                  `json:"event_type"`
	ReportedBy  MessageCheckpointReportedBy `json:"reported_by"`
	RetryNum    int                         `json:"retry_num"`
	MessageType event.MessageType           `json:"message_type,omitempty"`
	Info        string                      `json:"info,omitempty"`

	OriginalEventID  id.EventID `json:"original_event_id"`
	ManualRetryCount int        `json:"manual_retry_count"`
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
		Timestamp:  time.Now().UnixNano() / int64(time.Millisecond),
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

func (br *Bridge) SendMessageSuccessCheckpoint(evt *event.Event, step MessageCheckpointStep, retryNum int) {
	br.SendMessageCheckpoint(evt, step, nil, MsgStatusSuccess, retryNum)
}

func (br *Bridge) SendMessageErrorCheckpoint(evt *event.Event, step MessageCheckpointStep, err error, permanent bool, retryNum int) {
	status := MsgStatusWillRetry
	if permanent {
		status = MsgStatusPermFailure
	}
	br.SendMessageCheckpoint(evt, step, err, status, retryNum)
}

func (br *Bridge) SendMessageCheckpoint(evt *event.Event, step MessageCheckpointStep, err error, status MessageCheckpointStatus, retryNum int) {
	checkpoint := NewMessageCheckpoint(evt, step, status, retryNum)
	if err != nil {
		checkpoint.Info = err.Error()
	}
	go checkpoint.Send(br)
}

func (cp *MessageCheckpoint) Send(br *Bridge) {
	err := SendMessageCheckpoints(br, []*MessageCheckpoint{cp})
	if err != nil {
		br.Log.Warnfln("Error sending checkpoint %s/%s for %s: %v", cp.Step, cp.Status, cp.EventID, err)
	}
}

type CheckpointsJSON struct {
	Checkpoints []*MessageCheckpoint `json:"checkpoints"`
}

func SendMessageCheckpoints(br *Bridge, checkpoints []*MessageCheckpoint) error {
	checkpointsJSON := CheckpointsJSON{Checkpoints: checkpoints}

	if br.AS.HasWebsocket() {
		return br.AS.SendWebsocket(&appservice.WebsocketRequest{
			Command: "message_checkpoint",
			Data:    checkpointsJSON,
		})
	}

	endpoint := br.Config.Homeserver.MessageSendCheckpointEndpoint
	if endpoint == "" {
		return nil
	}

	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(checkpointsJSON); err != nil {
		return fmt.Errorf("failed to encode message send checkpoint JSON: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &body)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+br.AS.Registration.AppToken)
	req.Header.Set("User-Agent", mautrix.DefaultUserAgent+" checkpoint sender")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send bridge state update: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		respBody, _ := ioutil.ReadAll(resp.Body)
		if respBody != nil {
			respBody = bytes.ReplaceAll(respBody, []byte("\n"), []byte("\\n"))
		}
		return fmt.Errorf("unexpected status code %d sending bridge state update: %s", resp.StatusCode, respBody)
	}
	return nil
}
