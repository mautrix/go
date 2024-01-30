// Copyright (c) 2021 Sumner Evans
// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridge

import (
	"github.com/element-hq/mautrix-go/appservice"
	"github.com/element-hq/mautrix-go/bridge/status"
	"github.com/element-hq/mautrix-go/event"
)

func (br *Bridge) SendMessageSuccessCheckpoint(evt *event.Event, step status.MessageCheckpointStep, retryNum int) {
	br.SendMessageCheckpoint(evt, step, nil, status.MsgStatusSuccess, retryNum)
}

func (br *Bridge) SendMessageErrorCheckpoint(evt *event.Event, step status.MessageCheckpointStep, err error, permanent bool, retryNum int) {
	s := status.MsgStatusWillRetry
	if permanent {
		s = status.MsgStatusPermFailure
	}
	br.SendMessageCheckpoint(evt, step, err, s, retryNum)
}

func (br *Bridge) SendMessageCheckpoint(evt *event.Event, step status.MessageCheckpointStep, err error, s status.MessageCheckpointStatus, retryNum int) {
	checkpoint := status.NewMessageCheckpoint(evt, step, s, retryNum)
	if err != nil {
		checkpoint.Info = err.Error()
	}
	go br.SendRawMessageCheckpoint(checkpoint)
}

func (br *Bridge) SendRawMessageCheckpoint(cp *status.MessageCheckpoint) {
	err := br.SendMessageCheckpoints([]*status.MessageCheckpoint{cp})
	if err != nil {
		br.ZLog.Warn().Err(err).Interface("message_checkpoint", cp).Msg("Error sending message checkpoint")
	} else {
		br.ZLog.Debug().Interface("message_checkpoint", cp).Msg("Sent message checkpoint")
	}
}

func (br *Bridge) SendMessageCheckpoints(checkpoints []*status.MessageCheckpoint) error {
	checkpointsJSON := status.CheckpointsJSON{Checkpoints: checkpoints}

	if br.Websocket {
		return br.AS.SendWebsocket(&appservice.WebsocketRequest{
			Command: "message_checkpoint",
			Data:    checkpointsJSON,
		})
	}

	endpoint := br.Config.Homeserver.MessageSendCheckpointEndpoint
	if endpoint == "" {
		return nil
	}

	return checkpointsJSON.SendHTTP(endpoint, br.AS.Registration.AppToken)
}
