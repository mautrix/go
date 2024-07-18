// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/ptr"
	"go.mau.fi/util/variationselector"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func (portal *Portal) doForwardBackfill(ctx context.Context, source *UserLogin, lastMessage *database.Message) {
	log := zerolog.Ctx(ctx).With().Str("action", "forward backfill").Logger()
	ctx = log.WithContext(ctx)
	api, ok := source.Client.(BackfillingNetworkAPI)
	if !ok {
		log.Debug().Msg("Network API does not support backfilling")
		return
	}
	logEvt := log.Info()
	var limit int
	if lastMessage != nil {
		logEvt = logEvt.Str("latest_message_id", string(lastMessage.ID))
		limit = portal.Bridge.Config.Backfill.MaxCatchupMessages
	} else {
		logEvt = logEvt.Str("latest_message_id", "")
		limit = portal.Bridge.Config.Backfill.MaxInitialMessages
	}
	if limit <= 0 {
		logEvt.Discard().Send()
		return
	}
	logEvt.Msg("Fetching messages for forward backfill")
	resp, err := api.FetchMessages(ctx, FetchMessagesParams{
		Portal:        portal,
		ThreadRoot:    "",
		Forward:       true,
		AnchorMessage: lastMessage,
		Count:         limit,
	})
	if err != nil {
		log.Err(err).Msg("Failed to fetch messages for forward backfill")
		return
	} else if len(resp.Messages) == 0 {
		log.Debug().Msg("No messages to backfill")
		return
	}
	// TODO mark backfill queue task as done if last message is nil (-> room was empty) and HasMore is false?
	resp.Messages = cutoffMessages(&log, resp.Messages, true, lastMessage)
	if len(resp.Messages) == 0 {
		log.Warn().Msg("No messages left to backfill after cutting off old messages")
		return
	}
	portal.sendBackfill(ctx, source, resp.Messages, true, resp.MarkRead, false)
}

func (portal *Portal) DoBackwardsBackfill(ctx context.Context, source *UserLogin, task *database.BackfillTask) error {
	log := zerolog.Ctx(ctx)
	api, ok := source.Client.(BackfillingNetworkAPI)
	if !ok {
		return fmt.Errorf("network API does not support backfilling")
	}
	firstMessage, err := portal.Bridge.DB.Message.GetFirstPortalMessage(ctx, portal.PortalKey)
	if err != nil {
		return fmt.Errorf("failed to get first portal message: %w", err)
	}
	logEvt := log.Info().
		Str("cursor", string(task.Cursor)).
		Str("task_oldest_message_id", string(task.OldestMessageID)).
		Int("current_batch_count", task.BatchCount)
	if firstMessage != nil {
		logEvt = logEvt.Str("db_oldest_message_id", string(firstMessage.ID))
	} else {
		logEvt = logEvt.Str("db_oldest_message_id", "")
	}
	logEvt.Msg("Fetching messages for backward backfill")
	resp, err := api.FetchMessages(ctx, FetchMessagesParams{
		Portal:        portal,
		ThreadRoot:    "",
		Forward:       false,
		Cursor:        task.Cursor,
		AnchorMessage: firstMessage,
		Count:         portal.Bridge.Config.Backfill.Queue.BatchSize,
	})
	if err != nil {
		return fmt.Errorf("failed to fetch messages for backward backfill: %w", err)
	}
	log.Debug().
		Str("new_cursor", string(resp.Cursor)).
		Bool("has_more", resp.HasMore).
		Int("message_count", len(resp.Messages)).
		Msg("Fetched messages for backward backfill")
	task.Cursor = resp.Cursor
	if !resp.HasMore {
		task.IsDone = true
	}
	if len(resp.Messages) == 0 {
		if !resp.HasMore {
			log.Debug().Msg("No messages to backfill, marking backfill task as done")
		} else {
			log.Warn().Msg("No messages to backfill, but HasMore is true")
		}
		return nil
	}
	resp.Messages = cutoffMessages(log, resp.Messages, false, firstMessage)
	if len(resp.Messages) == 0 {
		return fmt.Errorf("no messages left to backfill after cutting off too new messages")
	}
	portal.sendBackfill(ctx, source, resp.Messages, false, resp.MarkRead, false)
	if len(resp.Messages) > 0 {
		task.OldestMessageID = resp.Messages[0].ID
	}
	return nil
}

func (portal *Portal) doThreadBackfill(ctx context.Context, source *UserLogin, threadID networkid.MessageID) {
	log := zerolog.Ctx(ctx).With().
		Str("subaction", "thread backfill").
		Str("thread_id", string(threadID)).
		Logger()
	log.Info().Msg("Backfilling thread inside other backfill")
	anchorMessage, err := portal.Bridge.DB.Message.GetLastThreadMessage(ctx, portal.PortalKey, threadID)
	if err != nil {
		log.Err(err).Msg("Failed to get last thread message")
		return
	}
	resp, err := source.Client.(BackfillingNetworkAPI).FetchMessages(ctx, FetchMessagesParams{
		Portal:        portal,
		ThreadRoot:    threadID,
		Forward:       true,
		AnchorMessage: anchorMessage,
		Count:         portal.Bridge.Config.Backfill.Threads.MaxInitialMessages,
	})
	if err != nil {
		log.Err(err).Msg("Failed to fetch messages for thread backfill")
		return
	} else if len(resp.Messages) == 0 {
		log.Debug().Msg("No messages to backfill")
		return
	}
	resp.Messages = cutoffMessages(&log, resp.Messages, true, anchorMessage)
	if len(resp.Messages) == 0 {
		log.Warn().Msg("No messages left to backfill after cutting off old messages")
		return
	}
	portal.sendBackfill(ctx, source, resp.Messages, true, resp.MarkRead, true)
}

func cutoffMessages(log *zerolog.Logger, messages []*BackfillMessage, forward bool, lastMessage *database.Message) []*BackfillMessage {
	if lastMessage == nil {
		return messages
	}
	if forward {
		var cutoff int
		for i, msg := range messages {
			if msg.ID == lastMessage.ID || msg.Timestamp.Before(lastMessage.Timestamp) {
				cutoff = i
			} else {
				break
			}
		}
		if cutoff != 0 {
			log.Debug().
				Int("cutoff_count", cutoff).
				Int("total_count", len(messages)).
				Time("last_bridged_ts", lastMessage.Timestamp).
				Msg("Cutting off forward backfill messages older than latest bridged message")
			messages = messages[cutoff:]
		}
	} else {
		cutoff := -1
		for i := len(messages) - 1; i >= 0; i-- {
			if messages[i].ID == lastMessage.ID || messages[i].Timestamp.After(lastMessage.Timestamp) {
				cutoff = i
			} else {
				break
			}
		}
		if cutoff != -1 {
			log.Debug().
				Int("cutoff_count", len(messages)-cutoff).
				Int("total_count", len(messages)).
				Time("oldest_bridged_ts", lastMessage.Timestamp).
				Msg("Cutting off backward backfill messages newer than oldest bridged message")
			messages = messages[cutoff:]
		}
	}
	return messages
}

func (portal *Portal) sendBackfill(ctx context.Context, source *UserLogin, messages []*BackfillMessage, forceForward, markRead, inThread bool) {
	canBatchSend := portal.Bridge.Matrix.GetCapabilities().BatchSending
	unreadThreshold := time.Duration(portal.Bridge.Config.Backfill.UnreadHoursThreshold) * time.Hour
	forceMarkRead := unreadThreshold > 0 && time.Since(messages[len(messages)-1].Timestamp) > unreadThreshold
	zerolog.Ctx(ctx).Info().
		Int("message_count", len(messages)).
		Bool("batch_send", canBatchSend).
		Bool("mark_read", markRead).
		Bool("mark_read_past_threshold", forceMarkRead).
		Msg("Sending backfill messages")
	if canBatchSend {
		portal.sendBatch(ctx, source, messages, forceForward, markRead || forceMarkRead)
	} else {
		portal.sendLegacyBackfill(ctx, source, messages, markRead || forceMarkRead)
	}
	zerolog.Ctx(ctx).Debug().Msg("Backfill finished")
	if !inThread && portal.Bridge.Config.Backfill.Threads.MaxInitialMessages > 0 {
		for _, msg := range messages {
			if msg.ShouldBackfillThread {
				portal.doThreadBackfill(ctx, source, msg.ID)
			}
		}
	}
}

func (portal *Portal) sendBatch(ctx context.Context, source *UserLogin, messages []*BackfillMessage, forceForward, markRead bool) {
	req := &mautrix.ReqBeeperBatchSend{
		ForwardIfNoMessages: !forceForward,
		Forward:             forceForward,
		Events:              make([]*event.Event, 0, len(messages)),
	}
	if markRead {
		req.MarkReadBy = source.UserMXID
	} else {
		req.SendNotification = forceForward
	}
	prevThreadEvents := make(map[networkid.MessageID]id.EventID)
	dbMessages := make([]*database.Message, 0, len(messages))
	dbReactions := make([]*database.Reaction, 0)
	extras := make([]*MatrixSendExtra, 0, len(messages))
	var disappearingMessages []*database.DisappearingMessage
	for _, msg := range messages {
		intent := portal.GetIntentFor(ctx, msg.Sender, source, RemoteEventMessage)
		replyTo, threadRoot, prevThreadEvent := portal.getRelationMeta(ctx, msg.ID, msg.ReplyTo, msg.ThreadRoot, true)
		if threadRoot != nil && prevThreadEvents[*msg.ThreadRoot] != "" {
			prevThreadEvent.MXID = prevThreadEvents[*msg.ThreadRoot]
		}
		var partIDs []networkid.PartID
		partMap := make(map[networkid.PartID]*database.Message, len(msg.Parts))
		for _, part := range msg.Parts {
			partIDs = append(partIDs, part.ID)
			portal.applyRelationMeta(part.Content, replyTo, threadRoot, prevThreadEvent)
			evtID := portal.Bridge.Matrix.GenerateDeterministicEventID(portal.MXID, portal.PortalKey, msg.ID, part.ID)
			req.Events = append(req.Events, &event.Event{
				Sender:    intent.GetMXID(),
				Type:      part.Type,
				Timestamp: msg.Timestamp.UnixMilli(),
				ID:        evtID,
				RoomID:    portal.MXID,
				Content: event.Content{
					Parsed: part.Content,
					Raw:    part.Extra,
				},
			})
			dbMessage := &database.Message{
				ID:         msg.ID,
				PartID:     part.ID,
				MXID:       evtID,
				Room:       portal.PortalKey,
				SenderID:   msg.Sender.Sender,
				SenderMXID: intent.GetMXID(),
				Timestamp:  msg.Timestamp,
				ThreadRoot: ptr.Val(msg.ThreadRoot),
				ReplyTo:    ptr.Val(msg.ReplyTo),
				Metadata:   part.DBMetadata,
			}
			partMap[part.ID] = dbMessage
			extras = append(extras, &MatrixSendExtra{MessageMeta: dbMessage})
			dbMessages = append(dbMessages, dbMessage)
			if prevThreadEvent != nil {
				prevThreadEvent.MXID = evtID
				prevThreadEvents[*msg.ThreadRoot] = evtID
			}
			if msg.Disappear.Type != database.DisappearingTypeNone {
				if msg.Disappear.Type == database.DisappearingTypeAfterSend && msg.Disappear.DisappearAt.IsZero() {
					msg.Disappear.DisappearAt = msg.Timestamp.Add(msg.Disappear.Timer)
				}
				disappearingMessages = append(disappearingMessages, &database.DisappearingMessage{
					RoomID:              portal.MXID,
					EventID:             evtID,
					DisappearingSetting: msg.Disappear,
				})
			}
		}
		slices.Sort(partIDs)
		for _, reaction := range msg.Reactions {
			reactionIntent := portal.GetIntentFor(ctx, reaction.Sender, source, RemoteEventReactionRemove)
			if reaction.TargetPart == nil {
				reaction.TargetPart = &partIDs[0]
			}
			if reaction.Timestamp.IsZero() {
				reaction.Timestamp = msg.Timestamp.Add(10 * time.Millisecond)
			}
			targetPart, ok := partMap[*reaction.TargetPart]
			if !ok {
				// TODO warning log and/or skip reaction?
			}
			reactionMXID := portal.Bridge.Matrix.GenerateReactionEventID(portal.MXID, targetPart, reaction.Sender.Sender, reaction.EmojiID)
			dbReaction := &database.Reaction{
				Room:          portal.PortalKey,
				MessageID:     msg.ID,
				MessagePartID: *reaction.TargetPart,
				SenderID:      reaction.Sender.Sender,
				EmojiID:       reaction.EmojiID,
				MXID:          reactionMXID,
				Timestamp:     reaction.Timestamp,
				Emoji:         reaction.Emoji,
				Metadata:      reaction.DBMetadata,
			}
			req.Events = append(req.Events, &event.Event{
				Sender:    reactionIntent.GetMXID(),
				Type:      event.EventReaction,
				Timestamp: reaction.Timestamp.UnixMilli(),
				ID:        reactionMXID,
				RoomID:    portal.MXID,
				Content: event.Content{
					Parsed: &event.ReactionEventContent{
						RelatesTo: event.RelatesTo{
							Type:    event.RelAnnotation,
							EventID: portal.Bridge.Matrix.GenerateDeterministicEventID(portal.MXID, portal.PortalKey, msg.ID, *reaction.TargetPart),
							Key:     variationselector.Add(reaction.Emoji),
						},
					},
					Raw: reaction.ExtraContent,
				},
			})
			dbReactions = append(dbReactions, dbReaction)
			extras = append(extras, &MatrixSendExtra{ReactionMeta: dbReaction})
		}
	}
	_, err := portal.Bridge.Matrix.BatchSend(ctx, portal.MXID, req, extras)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to send backfill messages")
	}
	if len(disappearingMessages) > 0 {
		// TODO mass insert disappearing messages
		go func() {
			for _, msg := range disappearingMessages {
				portal.Bridge.DisappearLoop.Add(ctx, msg)
			}
		}()
	}
	// TODO mass insert db messages
	for _, msg := range dbMessages {
		err = portal.Bridge.DB.Message.Insert(ctx, msg)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).
				Str("message_id", string(msg.ID)).
				Str("part_id", string(msg.PartID)).
				Msg("Failed to insert backfilled message to database")
		}
	}
}

func (portal *Portal) sendLegacyBackfill(ctx context.Context, source *UserLogin, messages []*BackfillMessage, markRead bool) {
	var lastPart id.EventID
	for _, msg := range messages {
		intent := portal.GetIntentFor(ctx, msg.Sender, source, RemoteEventMessage)
		dbMessages := portal.sendConvertedMessage(ctx, msg.ID, intent, msg.Sender, msg.ConvertedMessage, msg.Timestamp, func(z *zerolog.Event) *zerolog.Event {
			return z.
				Str("message_id", string(msg.ID)).
				Any("sender_id", msg.Sender).
				Time("message_ts", msg.Timestamp)
		})
		if len(dbMessages) > 0 {
			lastPart = dbMessages[len(dbMessages)-1].MXID
			for _, reaction := range msg.Reactions {
				reactionIntent := portal.GetIntentFor(ctx, reaction.Sender, source, RemoteEventReaction)
				targetPart := dbMessages[0]
				if reaction.TargetPart != nil {
					targetPartIdx := slices.IndexFunc(dbMessages, func(dbMsg *database.Message) bool {
						return dbMsg.PartID == *reaction.TargetPart
					})
					if targetPartIdx != -1 {
						targetPart = dbMessages[targetPartIdx]
					} else {
						// TODO warning log and/or skip reaction?
					}
				}
				portal.sendConvertedReaction(
					ctx, reaction.Sender.Sender, reactionIntent, targetPart, reaction.EmojiID, reaction.Emoji,
					reaction.Timestamp, reaction.DBMetadata, reaction.ExtraContent,
					func(z *zerolog.Event) *zerolog.Event {
						return z.
							Str("target_message_id", string(msg.ID)).
							Str("target_part_id", string(targetPart.PartID)).
							Any("reaction_sender_id", reaction.Sender).
							Time("reaction_ts", reaction.Timestamp)
					},
				)
			}
		}
	}
	if markRead {
		dp := source.User.DoublePuppet(ctx)
		if dp != nil {
			err := dp.MarkRead(ctx, portal.MXID, lastPart, time.Now())
			if err != nil {
				zerolog.Ctx(ctx).Err(err).Msg("Failed to mark room as read after backfill")
			}
		}
	}
}
