// Copyright (c) 2026 Killian Lelong
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type MatrixViewLimitedMedia struct {
	Portal  *Portal
	Message *database.Message
	Content *event.BeeperViewLimitedMedia
}

type ViewLimitedMediaHandlingNetworkAPI interface {
	HandleMatrixViewLimitedMedia(context.Context, *MatrixViewLimitedMedia) error
}

func (br *Bridge) ViewLimitedMedia(ctx context.Context, login *UserLogin, mxid id.EventID, request json.RawMessage) error {
	if login == nil || login.Client == nil || !login.Client.IsLoggedIn() {
		return mautrix.MForbidden.WithMessage("Login is disconnected")
	}
	limit, err := parseViewLimitedRequest(request)
	if err != nil {
		return mautrix.MInvalidParam.WithMessage("Invalid view limit")
	}
	msg, err := br.DB.Message.GetPartByMXID(ctx, mxid)
	if err != nil {
		return err
	}
	if msg == nil {
		return mautrix.MNotFound.WithMessage("Message not found")
	}
	up, err := br.DB.UserPortal.Get(ctx, login.UserLogin, msg.Room)
	if err != nil {
		return err
	}
	if up == nil || msg.Room.Receiver != "" && msg.Room.Receiver != login.ID {
		return mautrix.MNotFound.WithMessage("Message not found")
	}
	portal, err := br.GetExistingPortalByKey(ctx, msg.Room)
	if err != nil {
		return err
	}
	if portal == nil || portal.MXID == "" {
		return mautrix.MNotFound.WithMessage("Room not found")
	}
	portal.viewLimitedLock.Lock()
	defer portal.viewLimitedLock.Unlock()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	checker, ok := br.Bot.(interface {
		IsEventRedacted(context.Context, id.RoomID, id.EventID) (bool, error)
	})
	if !ok {
		return errors.New("matrix intent cannot check message redaction")
	}
	redacted, err := checker.IsEventRedacted(ctx, portal.MXID, mxid)
	if err != nil {
		return err
	}
	if redacted {
		return mautrix.MInvalidParam.WithMessage("Message was already consumed")
	}
	handler, ok := login.Client.(ViewLimitedMediaHandlingNetworkAPI)
	if !ok {
		return mautrix.MUnrecognized.WithMessage("View-limited media is not supported by this bridge")
	}
	if err = handler.HandleMatrixViewLimitedMedia(ctx, &MatrixViewLimitedMedia{portal, msg, &limit}); err != nil {
		return err
	}
	if limit.Count > 1 {
		return br.sendViewLimitedUpdate(ctx, portal.MXID, mxid, limit.Count-1)
	}
	if limit.Time > 0 {
		now := time.Now()
		return br.DisappearLoop.Add(ctx, &database.DisappearingMessage{
			RoomID: portal.MXID, EventID: mxid, Timestamp: now,
			DisappearingSetting: database.DisappearingSetting{
				Type: "view_limited", DisappearAt: now.Add(time.Duration(limit.Time) * time.Millisecond),
			},
		})
	}
	_, err = br.sendDisappearRedaction(ctx, portal.MXID, mxid, true)
	return err
}

func (br *Bridge) sendViewLimitedUpdate(ctx context.Context, roomID id.RoomID, eventID id.EventID, remaining int) error {
	_, err := br.Bot.SendMessage(ctx, roomID, event.BeeperViewLimitedMediaUpdate, &event.Content{Parsed: &event.BeeperViewLimitedMediaUpdateContent{
		Count:     remaining,
		RelatesTo: event.RelatesTo{Type: event.RelReference, EventID: eventID},
	}}, &MatrixSendExtra{TransactionID: fmt.Sprintf("view_limited_%s_%d", eventID, remaining)})
	return err
}

func (br *Bridge) sendDisappearRedaction(ctx context.Context, roomID id.RoomID, eventID id.EventID, viewLimited bool) (*mautrix.RespSendEvent, error) {
	content := &event.Content{
		Parsed: &event.RedactionEventContent{Redacts: eventID, Reason: "Message disappeared"},
	}
	var extra *MatrixSendExtra
	if viewLimited {
		content.Raw = map[string]any{"com.beeper.view_limited": true}
		extra = &MatrixSendExtra{TransactionID: "disappear_" + string(eventID)}
	}
	return br.Bot.SendMessage(ctx, roomID, event.EventRedaction, content, extra)
}

func parseViewLimitedRequest(data []byte) (event.BeeperViewLimitedMedia, error) {
	var content map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&content); err != nil {
		return event.BeeperViewLimitedMedia{}, err
	}
	if decoder.Decode(new(any)) != io.EOF || content == nil {
		return event.BeeperViewLimitedMedia{}, errors.New("invalid view limit request")
	}
	value, ok := content["com.beeper.view_limited"].(map[string]any)
	if !ok {
		return event.BeeperViewLimitedMedia{}, errors.New("missing view limit")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return event.BeeperViewLimitedMedia{}, err
	}
	var limit event.BeeperViewLimitedMedia
	if err = json.Unmarshal(encoded, &limit); err != nil {
		return event.BeeperViewLimitedMedia{}, errors.New("invalid view limit")
	}
	maxTime := time.Until(time.Unix(0, math.MaxInt64).Add(-time.Minute)).Milliseconds()
	validCount := limit.Type == "count" && limit.Count > 0 && limit.Time >= 0
	validTime := limit.Type == "time" && limit.Count == 0 && limit.Time > 0
	if (!validCount && !validTime) || limit.Time > maxTime {
		return event.BeeperViewLimitedMedia{}, errors.New("invalid view limit")
	}
	return limit, nil
}
