// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package simplevent

import (
	"context"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
)

// Message is a simple implementation of [bridgev2.RemoteMessage], [bridgev2.RemoteEdit] and [bridgev2.RemoteMessageUpsert].
type Message[T any] struct {
	EventMeta
	Data T

	ID            networkid.MessageID
	TransactionID networkid.TransactionID
	TargetMessage networkid.MessageID

	ConvertMessageFunc func(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, data T) (*bridgev2.ConvertedMessage, error)
	ConvertEditFunc    func(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, existing []*database.Message, data T) (*bridgev2.ConvertedEdit, error)
	HandleExistingFunc func(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, existing []*database.Message, data T) (bridgev2.UpsertResult, error)
}

var (
	_ bridgev2.RemoteMessage                  = (*Message[any])(nil)
	_ bridgev2.RemoteEdit                     = (*Message[any])(nil)
	_ bridgev2.RemoteMessageUpsert            = (*Message[any])(nil)
	_ bridgev2.RemoteMessageWithTransactionID = (*Message[any])(nil)
)

func (evt *Message[T]) ConvertMessage(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI) (*bridgev2.ConvertedMessage, error) {
	return evt.ConvertMessageFunc(ctx, portal, intent, evt.Data)
}

func (evt *Message[T]) ConvertEdit(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, existing []*database.Message) (*bridgev2.ConvertedEdit, error) {
	return evt.ConvertEditFunc(ctx, portal, intent, existing, evt.Data)
}

func (evt *Message[T]) HandleExisting(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, existing []*database.Message) (bridgev2.UpsertResult, error) {
	return evt.HandleExistingFunc(ctx, portal, intent, existing, evt.Data)
}

func (evt *Message[T]) GetID() networkid.MessageID {
	return evt.ID
}

func (evt *Message[T]) GetTargetMessage() networkid.MessageID {
	return evt.TargetMessage
}

func (evt *Message[T]) GetTransactionID() networkid.TransactionID {
	return evt.TransactionID
}

// PreConvertedMessage is a simple implementation of [bridgev2.RemoteMessage] with pre-converted data.
type PreConvertedMessage struct {
	EventMeta
	Data          *bridgev2.ConvertedMessage
	ID            networkid.MessageID
	TransactionID networkid.TransactionID

	HandleExistingFunc func(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, existing []*database.Message) (bridgev2.UpsertResult, error)
}

var (
	_ bridgev2.RemoteMessage                  = (*PreConvertedMessage)(nil)
	_ bridgev2.RemoteMessageUpsert            = (*PreConvertedMessage)(nil)
	_ bridgev2.RemoteMessageWithTransactionID = (*PreConvertedMessage)(nil)
)

func (evt *PreConvertedMessage) ConvertMessage(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI) (*bridgev2.ConvertedMessage, error) {
	return evt.Data, nil
}

func (evt *PreConvertedMessage) GetID() networkid.MessageID {
	return evt.ID
}

func (evt *PreConvertedMessage) GetTransactionID() networkid.TransactionID {
	return evt.TransactionID
}

func (evt *PreConvertedMessage) HandleExisting(ctx context.Context, portal *bridgev2.Portal, intent bridgev2.MatrixAPI, existing []*database.Message) (bridgev2.UpsertResult, error) {
	if evt.HandleExistingFunc == nil {
		return bridgev2.UpsertResult{}, nil
	}
	return evt.HandleExistingFunc(ctx, portal, intent, existing)
}

type MessageRemove struct {
	EventMeta

	TargetMessage networkid.MessageID
	OnlyForMe     bool
}

var (
	_ bridgev2.RemoteMessageRemove   = (*MessageRemove)(nil)
	_ bridgev2.RemoteDeleteOnlyForMe = (*MessageRemove)(nil)
)

func (evt *MessageRemove) GetTargetMessage() networkid.MessageID {
	return evt.TargetMessage
}

func (evt *MessageRemove) DeleteOnlyForMe() bool {
	return evt.OnlyForMe
}
