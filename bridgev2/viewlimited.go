// Copyright (c) 2026 Killian Lelong
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"go.mau.fi/util/exerrors"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type MatrixViewLimitedMedia struct {
	Portal  *Portal
	Message *database.Message
	Content *event.BeeperViewLimitedMedia
}

// ViewLimitedMediaHandlingNetworkAPI reports opens; errors expire media without a provider retry.
type ViewLimitedMediaHandlingNetworkAPI interface {
	HandleMatrixViewLimitedMedia(context.Context, *MatrixViewLimitedMedia) error
}

type viewLimitedMediaState struct {
	limit string
	hash  string
}

func prepareViewLimitedMedia(content *event.Content) (*viewLimitedMediaState, error) {
	if parsed, ok := content.Parsed.(*event.MessageEventContent); (!ok || parsed.BeeperViewLimited == nil) && content.Raw["com.beeper.view_limited"] == nil {
		return nil, nil
	}
	data, err := json.Marshal(content)
	if err != nil {
		return nil, err
	}
	parsed, hash, err := parseViewLimitedContent(data)
	if err != nil {
		return nil, err
	}
	limit := exerrors.Must(json.Marshal(parsed["com.beeper.view_limited"]))
	return &viewLimitedMediaState{string(limit), hash}, nil
}

func (br *Bridge) saveViewLimitedMedia(ctx context.Context, mxid id.EventID, state *viewLimitedMediaState) error {
	if state == nil {
		return nil
	}
	return br.DB.PutViewLimited(ctx, mxid, state.limit, state.hash)
}

func (br *Bridge) ViewLimitedMedia(ctx context.Context, login *UserLogin, mxid id.EventID, request json.RawMessage) error {
	if login == nil || login.Client == nil || !login.Client.IsLoggedIn() {
		return mautrix.MForbidden.WithMessage("Login is disconnected")
	}
	requestValue, limit, requestJSON, err := parseViewLimitedRequest(request)
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
	stored, err := br.DB.GetViewLimited(ctx, mxid)
	if errors.Is(err, sql.ErrNoRows) {
		return mautrix.MInvalidParam.WithMessage("Not a view-limited message")
	}
	if err != nil {
		return err
	}
	if stored.State == "pending" {
		return mautrix.MUnknown.WithMessage("Media open is pending provider confirmation")
	}
	if stored.State == "apply" {
		if requestJSON != stored.Request && requestJSON != stored.Limit {
			return mautrix.MInvalidParam.WithMessage("Media open is stale")
		}
		if err = br.sendViewLimitedUpdate(ctx, msg, portal, stored); err != nil {
			return err
		}
		if requestJSON == stored.Request {
			return mautrix.MInvalidParam.WithMessage("Media open is stale")
		}
	}
	if stored.State != "ready" && stored.State != "apply" || requestJSON != stored.Limit {
		return mautrix.MInvalidParam.WithMessage("Media open is stale")
	}
	dm := &database.DisappearingMessage{RoomID: portal.MXID, EventID: mxid, Timestamp: time.Now(),
		DisappearingSetting: database.DisappearingSetting{Type: "view_limited_pending", DisappearAt: time.Now().Add(time.Minute)}}
	claimed, err := br.DB.ClaimViewLimited(ctx, mxid, stored.Hash, requestJSON, dm.Timestamp)
	if err != nil {
		return err
	}
	if !claimed {
		return mautrix.MUnknown.WithMessage("Media open already in progress")
	}
	br.DisappearLoop.Add(ctx, dm)
	// Once claimed, finish independently of the HTTP client's lifetime.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	if handler, ok := login.Client.(ViewLimitedMediaHandlingNetworkAPI); ok {
		if err = handler.HandleMatrixViewLimitedMedia(ctx, &MatrixViewLimitedMedia{portal, msg, &limit}); err != nil {
			dm.DisappearAt = time.Now()
			br.DisappearLoop.Add(context.WithoutCancel(ctx), dm)
			return err
		}
	}
	if limit.Type == "time" || limit.Count == 1 {
		dm.Type = "view_limited"
		dm.DisappearAt = time.Now().Add(time.Duration(limit.Time) * time.Millisecond)
		err = br.DB.DoTxn(ctx, nil, func(ctx context.Context) error {
			if err := br.DB.DisappearingMessage.Put(ctx, dm); err != nil {
				return err
			}
			return br.DB.UpdateViewLimited(ctx, mxid, "{}", "", "done")
		})
		if err == nil {
			br.DisappearLoop.Add(ctx, dm)
		}
		return err
	}
	requestValue["count"] = limit.Count - 1
	updatedLimit := exerrors.Must(json.Marshal(requestValue))
	if err = br.DB.UpdateViewLimited(ctx, mxid, string(updatedLimit), stored.Hash, "apply"); err != nil {
		return err
	}
	stored.Limit, stored.State = string(updatedLimit), "apply"
	return br.sendViewLimitedUpdate(ctx, msg, portal, stored)
}

func (br *Bridge) sendViewLimitedUpdate(ctx context.Context, msg *database.Message, portal *Portal, stored *database.ViewLimitedMessage) error {
	var limit event.BeeperViewLimitedMedia
	if err := json.Unmarshal([]byte(stored.Limit), &limit); err != nil || limit.Type != "count" || limit.Count < 1 {
		return fmt.Errorf("invalid stored view limit")
	}
	intent, err := portal.getIntentForMXID(ctx, msg.SenderMXID)
	if err != nil {
		return err
	}
	if intent == nil {
		return fmt.Errorf("original sender unavailable")
	}
	update := &event.BeeperViewLimitedUpdateEventContent{
		RelatesTo: event.RelatesTo{Type: event.RelReference, EventID: msg.MXID},
		Count:     limit.Count,
	}
	_, err = intent.SendMessage(ctx, portal.MXID, event.BeeperViewLimitedUpdate, &event.Content{Parsed: update},
		&MatrixSendExtra{TransactionID: fmt.Sprintf("view_limited_%s_%d", msg.MXID, limit.Count)})
	if err != nil {
		return err
	}
	return br.DB.UpdateViewLimited(ctx, msg.MXID, stored.Limit, stored.Hash, "ready")
}

func parseViewLimitedRequest(data []byte) (map[string]any, event.BeeperViewLimitedMedia, string, error) {
	var request map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&request); err != nil {
		return nil, event.BeeperViewLimitedMedia{}, "", err
	}
	if decoder.Decode(new(any)) != io.EOF || len(request) != 1 {
		return nil, event.BeeperViewLimitedMedia{}, "", errors.New("invalid view limit request")
	}
	value, ok := request["com.beeper.view_limited"].(map[string]any)
	if !ok {
		return nil, event.BeeperViewLimitedMedia{}, "", errors.New("missing view limit")
	}
	encoded := exerrors.Must(json.Marshal(value))
	var limit event.BeeperViewLimitedMedia
	err := json.Unmarshal(encoded, &limit)
	latestExpiry := time.Unix(0, math.MaxInt64).Add(-time.Minute)
	validCount := limit.Type == "count" && limit.Count > 0 && limit.Time == 0
	validTime := limit.Type == "time" && limit.Count == 0 && limit.Time > 0 && limit.Time <= time.Until(latestExpiry).Milliseconds()
	if err != nil || !validCount && !validTime {
		return nil, event.BeeperViewLimitedMedia{}, "", errors.New("invalid view limit")
	}
	return value, limit, string(encoded), nil
}

func parseViewLimitedContent(data []byte) (map[string]any, string, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var content map[string]any
	if err := decoder.Decode(&content); err != nil {
		return nil, "", fmt.Errorf("invalid message content: %w", err)
	}
	if content == nil {
		return nil, "", errors.New("invalid message content")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, "", errors.New("trailing message content")
	}
	// Double-puppet markers may be added after the original content is captured.
	delete(content, appservice.DoublePuppetKey)
	delete(content, appservice.DoublePuppetTSKey)
	return content, fmt.Sprintf("%x", sha256.Sum256(exerrors.Must(json.Marshal(content)))), nil
}
