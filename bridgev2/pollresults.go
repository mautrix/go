// Copyright (c) 2026 Automattic Inc.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/id"
)

type PollResults struct {
	Closed      bool
	TotalVoters int
	Answers     []*PollAnswerResult
}

type PollAnswerResult struct {
	ID           string
	Voters       int
	Chosen       bool
	RecentVoters []networkid.UserID
}

type RespPollResults struct {
	Closed      bool                    `json:"closed"`
	TotalVoters int                     `json:"total_voters"`
	Answers     []*RespPollAnswerResult `json:"answers"`
}

type RespPollAnswerResult struct {
	ID           string      `json:"id"`
	Voters       int         `json:"voters"`
	Chosen       bool        `json:"chosen,omitempty"`
	RecentVoters []id.UserID `json:"recent_voters,omitempty"`
}

func (br *Bridge) FetchPollResults(ctx context.Context, login *UserLogin, mxid id.EventID) (*RespPollResults, error) {
	if login == nil || login.Client == nil || !login.Client.IsLoggedIn() {
		return nil, mautrix.MForbidden.WithMessage("Login is disconnected")
	}
	handler, ok := login.Client.(PollResultsFetchingNetworkAPI)
	if !ok {
		return nil, mautrix.MUnrecognized.WithMessage("Fetching poll results is not supported by this bridge")
	}
	msg, err := br.DB.Message.GetPartByMXID(ctx, mxid)
	if err != nil {
		return nil, err
	} else if msg == nil || (msg.Room.Receiver != "" && msg.Room.Receiver != login.ID) {
		return nil, mautrix.MNotFound.WithMessage("Message not found")
	}
	portal, err := br.GetExistingPortalByKey(ctx, msg.Room)
	if err != nil {
		return nil, err
	} else if portal == nil || portal.MXID == "" {
		return nil, mautrix.MNotFound.WithMessage("Room not found")
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	results, err := handler.FetchPollResults(ctx, portal, msg)
	if err != nil {
		return nil, err
	} else if results == nil {
		return nil, mautrix.MNotFound.WithMessage("Poll not found")
	}
	resp := &RespPollResults{
		Closed:      results.Closed,
		TotalVoters: results.TotalVoters,
		Answers:     make([]*RespPollAnswerResult, len(results.Answers)),
	}
	for i, answer := range results.Answers {
		respAnswer := &RespPollAnswerResult{
			ID:           answer.ID,
			Voters:       answer.Voters,
			Chosen:       answer.Chosen,
			RecentVoters: make([]id.UserID, 0, len(answer.RecentVoters)),
		}
		for _, voter := range answer.RecentVoters {
			if login.Client.IsThisUser(ctx, voter) {
				respAnswer.RecentVoters = append(respAnswer.RecentVoters, login.UserMXID)
			} else {
				respAnswer.RecentVoters = append(respAnswer.RecentVoters, br.Matrix.GhostIntent(voter).GetMXID())
			}
		}
		resp.Answers[i] = respAnswer
	}
	return resp, nil
}
