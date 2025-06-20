// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/exp/slices"

	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type DisappearLoop struct {
	br        *Bridge
	NextCheck time.Time
	stop      atomic.Pointer[context.CancelFunc]
}

const DisappearCheckInterval = 1 * time.Hour

func (dl *DisappearLoop) Start() {
	log := dl.br.Log.With().Str("component", "disappear loop").Logger()
	ctx, stop := context.WithCancel(log.WithContext(context.Background()))
	if oldStop := dl.stop.Swap(&stop); oldStop != nil {
		(*oldStop)()
	}
	log.Debug().Msg("Disappearing message loop starting")
	for {
		dl.NextCheck = time.Now().Add(DisappearCheckInterval)
		messages, err := dl.br.DB.DisappearingMessage.GetUpcoming(ctx, DisappearCheckInterval)
		if err != nil {
			log.Err(err).Msg("Failed to get upcoming disappearing messages")
		} else if len(messages) > 0 {
			go dl.sleepAndDisappear(ctx, messages...)
		}
		select {
		case <-time.After(time.Until(dl.NextCheck)):
		case <-ctx.Done():
			log.Debug().Msg("Disappearing message loop stopping")
			return
		}
	}
}

func (dl *DisappearLoop) Stop() {
	if dl == nil {
		return
	}
	if stop := dl.stop.Load(); stop != nil {
		(*stop)()
	}
}

func (dl *DisappearLoop) StartAll(ctx context.Context, roomID id.RoomID) {
	startedMessages, err := dl.br.DB.DisappearingMessage.StartAll(ctx, roomID)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to start disappearing messages")
		return
	}
	startedMessages = slices.DeleteFunc(startedMessages, func(dm *database.DisappearingMessage) bool {
		return dm.DisappearAt.After(dl.NextCheck)
	})
	slices.SortFunc(startedMessages, func(a, b *database.DisappearingMessage) int {
		return a.DisappearAt.Compare(b.DisappearAt)
	})
	if len(startedMessages) > 0 {
		go dl.sleepAndDisappear(ctx, startedMessages...)
	}
}

func (dl *DisappearLoop) Add(ctx context.Context, dm *database.DisappearingMessage) {
	err := dl.br.DB.DisappearingMessage.Put(ctx, dm)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Stringer("event_id", dm.EventID).
			Msg("Failed to save disappearing message")
	}
	if !dm.DisappearAt.IsZero() && dm.DisappearAt.Before(dl.NextCheck) {
		go dl.sleepAndDisappear(zerolog.Ctx(ctx).WithContext(dl.br.BackgroundCtx), dm)
	}
}

func (dl *DisappearLoop) sleepAndDisappear(ctx context.Context, dms ...*database.DisappearingMessage) {
	for _, msg := range dms {
		select {
		case <-time.After(time.Until(msg.DisappearAt)):
		case <-ctx.Done():
			return
		}
		resp, err := dl.br.Bot.SendMessage(ctx, msg.RoomID, event.EventRedaction, &event.Content{
			Parsed: &event.RedactionEventContent{
				Redacts: msg.EventID,
				Reason:  "Message disappeared",
			},
		}, nil)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Stringer("target_event_id", msg.EventID).Msg("Failed to disappear message")
		} else {
			zerolog.Ctx(ctx).Debug().
				Stringer("target_event_id", msg.EventID).
				Stringer("redaction_event_id", resp.EventID).
				Msg("Disappeared message")
		}
		err = dl.br.DB.DisappearingMessage.Delete(ctx, msg.EventID)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).
				Stringer("event_id", msg.EventID).
				Msg("Failed to delete disappearing message entry from database")
		}
	}
}
