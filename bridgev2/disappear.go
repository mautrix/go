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
	nextCheck atomic.Pointer[time.Time]
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
		nextCheck := time.Now().Add(DisappearCheckInterval)
		dl.nextCheck.Store(&nextCheck)
		const MessageLimit = 200
		messages, err := dl.br.DB.DisappearingMessage.GetUpcoming(ctx, DisappearCheckInterval, MessageLimit)
		if err != nil {
			log.Err(err).Msg("Failed to get upcoming disappearing messages")
		} else if len(messages) > 0 {
			if len(messages) >= MessageLimit {
				lastDisappearTime := messages[len(messages)-1].DisappearAt
				log.Debug().
					Int("message_count", len(messages)).
					Time("last_due", lastDisappearTime).
					Msg("Deleting disappearing messages synchronously and checking again immediately")
				// Store the expected next check time to avoid Add spawning unnecessary goroutines.
				// This can be in the past, in which case Add will put everything in the db, which is also fine.
				dl.nextCheck.Store(&lastDisappearTime)
				// If there are many messages, process them synchronously and then check again.
				dl.sleepAndDisappear(ctx, messages...)
				continue
			}
			go dl.sleepAndDisappear(ctx, messages...)
		}
		select {
		case <-time.After(time.Until(dl.GetNextCheck())):
		case <-ctx.Done():
			log.Debug().Msg("Disappearing message loop stopping")
			return
		}
	}
}

func (dl *DisappearLoop) GetNextCheck() time.Time {
	if dl == nil {
		return time.Time{}
	}
	nextCheck := dl.nextCheck.Load()
	if nextCheck == nil {
		return time.Time{}
	}
	return *nextCheck
}

func (dl *DisappearLoop) Stop() {
	if dl == nil {
		return
	}
	if stop := dl.stop.Load(); stop != nil {
		(*stop)()
	}
}

func (dl *DisappearLoop) StartAllBefore(ctx context.Context, roomID id.RoomID, beforeTS time.Time) {
	startedMessages, err := dl.br.DB.DisappearingMessage.StartAllBefore(ctx, roomID, beforeTS)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to start disappearing messages")
		return
	}
	startedMessages = slices.DeleteFunc(startedMessages, func(dm *database.DisappearingMessage) bool {
		return dm.DisappearAt.After(dl.GetNextCheck())
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
	if !dm.DisappearAt.IsZero() && dm.DisappearAt.Before(dl.GetNextCheck()) {
		go dl.sleepAndDisappear(zerolog.Ctx(ctx).WithContext(dl.br.BackgroundCtx), dm)
	}
}

func (dl *DisappearLoop) sleepAndDisappear(ctx context.Context, dms ...*database.DisappearingMessage) {
	for _, msg := range dms {
		timeUntilDisappear := time.Until(msg.DisappearAt)
		if timeUntilDisappear <= 0 {
			if ctx.Err() != nil {
				return
			}
		} else {
			select {
			case <-time.After(timeUntilDisappear):
			case <-ctx.Done():
				return
			}
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
