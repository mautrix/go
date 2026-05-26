// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgeconfig

import (
	"fmt"
	"slices"
	"strings"
)

const (
	RejoinEventMessage         = "message"
	RejoinEventMessageUpsert   = "message_upsert"
	RejoinEventEdit            = "edit"
	RejoinEventReaction        = "reaction"
	RejoinEventReactionRemove  = "reaction_remove"
	RejoinEventReactionSync    = "reaction_sync"
	RejoinEventMessageRemove   = "message_remove"
	RejoinEventReadReceipt     = "read_receipt"
	RejoinEventDeliveryReceipt = "delivery_receipt"
	RejoinEventMarkUnread      = "mark_unread"
	RejoinEventTyping          = "typing"
	RejoinEventChatInfoChange  = "chat_info_change"
	RejoinEventChatResync      = "chat_resync"
	RejoinEventBackfill        = "backfill"
)

var (
	AllRejoinEventNames = []string{
		RejoinEventMessage,
		RejoinEventMessageUpsert,
		RejoinEventEdit,
		RejoinEventReaction,
		RejoinEventReactionRemove,
		RejoinEventReactionSync,
		RejoinEventMessageRemove,
		RejoinEventReadReceipt,
		RejoinEventDeliveryReceipt,
		RejoinEventMarkUnread,
		RejoinEventTyping,
		RejoinEventChatInfoChange,
		RejoinEventChatResync,
		RejoinEventBackfill,
	}
	DefaultRejoinOnEvents = []string{
		RejoinEventMessage,
		RejoinEventMessageUpsert,
		RejoinEventEdit,
		RejoinEventReaction,
		RejoinEventReactionRemove,
		RejoinEventReactionSync,
		RejoinEventMessageRemove,
		RejoinEventBackfill,
	}
)

type RejoinOnEvents []string

func (roe RejoinOnEvents) Contains(evtName string) bool {
	if roe == nil {
		return slices.Contains(DefaultRejoinOnEvents, evtName)
	}
	return slices.Contains(roe, evtName)
}

func (roe RejoinOnEvents) Validate() error {
	for _, evtName := range roe {
		if !slices.Contains(AllRejoinEventNames, evtName) {
			return fmt.Errorf("unknown bridge.rejoin_on_events value %q (allowed values: %s)", evtName, strings.Join(AllRejoinEventNames, ", "))
		}
	}
	return nil
}
