// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package provisionutil

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"go.mau.fi/util/exsync"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/simplevent"
	"maunium.net/go/mautrix/id"
)

type ReqResolveMedia struct {
	// The raw contents of the `com.beeper.unresolved_media` field in the message being resolved
	UnresolvedMedia json.RawMessage `json:"com.beeper.unresolved_media"`
}

type RespResolveMedia struct {
	// Nothing for now, will have raw contents for non-edit media later
}

var resolveMediaLocks = exsync.NewKeyedMutex[id.EventID]()

func ResolveMedia(ctx context.Context, login *bridgev2.UserLogin, eventID id.EventID, params *ReqResolveMedia) (*RespResolveMedia, error) {
	api, ok := login.Client.(bridgev2.MediaResolvingNetworkAPI)
	if !ok {
		return nil, mautrix.MUnrecognized.WithMessage("This bridge does not support resolving media")
	}
	defer resolveMediaLocks.WithLock(eventID)()
	log := zerolog.Ctx(ctx).With().Str("action", "resolve media").Logger()
	msg, err := login.Bridge.DB.Message.GetPartByMXID(ctx, eventID)
	if err != nil {
		log.Err(err).Msg("Failed to get message from database")
		return nil, mautrix.MUnknown.WithMessage("Failed to get message from database").WithInternalError(err)
	} else if msg == nil {
		return nil, mautrix.MNotFound.WithMessage("Target message not found")
	}
	portal, err := login.Bridge.GetExistingPortalByKey(ctx, msg.Room)
	if err != nil {
		log.Err(err).Msg("Failed to get portal from database")
		return nil, mautrix.MUnknown.WithMessage("Failed to get portal from database").WithInternalError(err)
	} else if portal == nil || portal.MXID == "" {
		return nil, mautrix.MNotFound.WithMessage("Target portal not found")
	}
	res, err := api.ResolveMedia(ctx, portal, msg, params.UnresolvedMedia)
	if err != nil {
		return nil, err
	}
	if res.Edit != nil {
		queueDone := make(chan struct{})
		editRes := login.QueueRemoteEvent(&simplevent.Message[any]{
			EventMeta: simplevent.EventMeta{
				Type: bridgev2.RemoteEventEdit,
				LogContext: func(c zerolog.Context) zerolog.Context {
					reqID, ok := hlog.IDFromCtx(ctx)
					if ok {
						c = c.Stringer("request_id", reqID)
					}
					return c.
						Str("edit_source", "resolve media").
						Stringer("resolve_media_target_id", eventID)
				},
				PortalKey: msg.Room,
				Sender:    bridgev2.EventSender{ForceEditOrigSender: true},
				Timestamp: time.Now(),
				PostHandleFunc: func(ctx context.Context, portal *bridgev2.Portal) {
					close(queueDone)
				},
			},
			TargetMessage: msg.ID,
			ConvertEditFunc: func(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, existing []*database.Message, data any) (*bridgev2.ConvertedEdit, error) {
				return &bridgev2.ConvertedEdit{
					ModifiedParts: []*bridgev2.ConvertedEditPart{res.Edit},
				}, nil
			},
		})
		if !editRes.Success {
			return nil, mautrix.MUnknown.WithMessage("Failed to send edit").WithInternalError(editRes.Error)
		}
		if editRes.Queued {
			log.Debug().Msg("Waiting for event handling to finish")
			select {
			case <-queueDone:
				log.Debug().Msg("Event handling finished")
			case <-ctx.Done():
				log.Warn().Msg("Context cancelled before event handling finished")
				return nil, ctx.Err()
			}
		}
	}
	return &RespResolveMedia{}, nil
}
