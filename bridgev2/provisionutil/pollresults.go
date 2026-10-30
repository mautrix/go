// Copyright (c) 2026 Automattic Inc.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package provisionutil

import (
	"context"

	"go.mau.fi/util/exslices"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/id"
)

func FetchPollResults(ctx context.Context, login *bridgev2.UserLogin, mxid id.EventID) (*bridgev2.PollResults, error) {
	if login.Client == nil || !login.Client.IsLoggedIn() {
		return nil, bridgev2.ErrNotLoggedIn
	}
	api, ok := login.Client.(bridgev2.PollResultsFetchingNetworkAPI)
	if !ok {
		return nil, bridgev2.RespError(mautrix.MUnrecognized.WithMessage("This bridge does not support fetching poll results"))
	}
	msg, err := login.Bridge.DB.Message.GetPartByMXID(ctx, mxid)
	if err != nil {
		return nil, err
	} else if msg == nil || (msg.Room.Receiver != "" && msg.Room.Receiver != login.ID) {
		return nil, bridgev2.RespError(mautrix.MNotFound.WithMessage("Message not found"))
	}
	portal, err := login.Bridge.GetExistingPortalByKey(ctx, msg.Room)
	if err != nil {
		return nil, err
	} else if portal == nil || portal.MXID == "" {
		return nil, bridgev2.RespError(mautrix.MNotFound.WithMessage("Room not found"))
	}
	results, err := api.FetchPollResults(ctx, portal, msg)
	if err != nil {
		return nil, err
	} else if results == nil {
		return nil, bridgev2.RespError(mautrix.MNotFound.WithMessage("Poll not found"))
	}
	for _, answer := range results.Answers {
		answer.RecentVoterMXIDs = exslices.CastFunc(answer.RecentVoters, func(voter networkid.UserID) id.UserID {
			if login.Client.IsThisUser(ctx, voter) {
				return login.UserMXID
			}
			return login.Bridge.Matrix.FormatGhostMXID(voter)
		})
	}
	return results, nil
}
