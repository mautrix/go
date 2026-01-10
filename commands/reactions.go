// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
)

const ReactionCommandsKey = "fi.mau.reaction_commands"
const ReactionMultiUseKey = "fi.mau.reaction_multi_use"

type ReactionCommandData struct {
	Command string `json:"command"`
	Args    any    `json:"args,omitempty"`
}

func (proc *Processor[MetaType]) ParseReaction(ctx context.Context, evt *event.Event) *Event[MetaType] {
	content, ok := evt.Content.Parsed.(*event.ReactionEventContent)
	if !ok {
		return nil
	}
	evtID := content.RelatesTo.EventID
	if evtID == "" || !strings.HasPrefix(content.RelatesTo.Key, proc.ReactionCommandPrefix) {
		return nil
	}
	targetEvt, err := proc.Client.GetEvent(ctx, evt.RoomID, evtID)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Stringer("target_event_id", evtID).Msg("Failed to get target event for reaction")
		return nil
	} else if targetEvt.Sender != proc.Client.UserID || targetEvt.Unsigned.RedactedBecause != nil {
		return nil
	}
	if targetEvt.Type == event.EventEncrypted {
		if proc.Client.Crypto == nil {
			zerolog.Ctx(ctx).Warn().
				Stringer("target_event_id", evtID).
				Msg("Received reaction to encrypted event, but don't have crypto helper in client")
			return nil
		}
		_ = targetEvt.Content.ParseRaw(targetEvt.Type)
		targetEvt, err = proc.Client.Crypto.Decrypt(ctx, targetEvt)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).
				Stringer("target_event_id", evtID).
				Msg("Failed to decrypt target event for reaction")
			return nil
		}
	}
	reactionCommands, ok := targetEvt.Content.Raw[ReactionCommandsKey].(map[string]any)
	if !ok {
		zerolog.Ctx(ctx).Trace().
			Stringer("target_event_id", evtID).
			Msg("Reaction target event doesn't have commands key")
		return nil
	}
	isMultiUse, _ := targetEvt.Content.Raw[ReactionMultiUseKey].(bool)
	rawCmd, ok := reactionCommands[content.RelatesTo.Key]
	if !ok {
		zerolog.Ctx(ctx).Debug().
			Stringer("target_event_id", evtID).
			Str("reaction_key", content.RelatesTo.Key).
			Msg("Reaction command not found in target event")
		return nil
	}
	var wrappedEvt *Event[MetaType]
	switch typedCmd := rawCmd.(type) {
	case string:
		wrappedEvt = RawTextToEvent[MetaType](ctx, evt, typedCmd)
	case map[string]any:
		var input event.MSC4391BotCommandInput
		if marshaled, err := json.Marshal(typedCmd); err != nil {

		} else if err = json.Unmarshal(marshaled, &input); err != nil {

		} else {
			wrappedEvt = StructuredCommandToEvent[MetaType](ctx, evt, &input)
		}
	}
	if wrappedEvt == nil {
		zerolog.Ctx(ctx).Debug().
			Stringer("target_event_id", evtID).
			Str("reaction_key", content.RelatesTo.Key).
			Msg("Reaction command data is invalid")
		return nil
	}
	wrappedEvt.Proc = proc
	wrappedEvt.Redact()
	if !isMultiUse {
		DeleteAllReactions(ctx, proc.Client, evt)
	}
	if wrappedEvt.Command == "" {
		return nil
	}
	return wrappedEvt
}

func DeleteAllReactionsCommandFunc[MetaType any](ce *Event[MetaType]) {
	DeleteAllReactions(ce.Ctx, ce.Proc.Client, ce.Event)
}

func DeleteAllReactions(ctx context.Context, client *mautrix.Client, evt *event.Event) {
	rel, ok := evt.Content.Parsed.(event.Relatable)
	if !ok {
		return
	}
	relation := rel.OptionalGetRelatesTo()
	if relation == nil {
		return
	}
	targetEvt := relation.GetReplyTo()
	if targetEvt == "" {
		targetEvt = relation.GetAnnotationID()
	}
	if targetEvt == "" {
		return
	}
	relations, err := client.GetRelations(ctx, evt.RoomID, targetEvt, &mautrix.ReqGetRelations{
		RelationType: event.RelAnnotation,
		EventType:    event.EventReaction,
		Limit:        20,
	})
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to get reactions to delete")
		return
	}
	for _, relEvt := range relations.Chunk {
		_, err = client.RedactEvent(ctx, relEvt.RoomID, relEvt.ID)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Stringer("event_id", relEvt.ID).Msg("Failed to redact reaction event")
		}
	}
}
