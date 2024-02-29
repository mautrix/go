// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package appservice

import (
	"context"
	"encoding/json"
	"runtime/debug"
	"time"

	"github.com/rs/zerolog"

	"github.com/element-hq/mautrix-go"
	"github.com/element-hq/mautrix-go/event"
)

type ExecMode uint8

const (
	AsyncHandlers ExecMode = iota
	AsyncLoop
	Sync
)

type EventHandler = func(ctx context.Context, evt *event.Event)
type OTKHandler = func(ctx context.Context, otk *mautrix.OTKCount)
type DeviceListHandler = func(ctx context.Context, lists *mautrix.DeviceLists, since string)

type EventProcessor struct {
	ExecMode ExecMode

	ExecSyncWarnTime time.Duration
	ExecSyncTimeout  time.Duration

	as       *AppService
	stop     chan struct{}
	handlers map[event.Type][]EventHandler

	otkHandlers        []OTKHandler
	deviceListHandlers []DeviceListHandler
}

func NewEventProcessor(as *AppService) *EventProcessor {
	return &EventProcessor{
		ExecMode: AsyncHandlers,
		as:       as,
		stop:     make(chan struct{}, 1),
		handlers: make(map[event.Type][]EventHandler),

		ExecSyncWarnTime: 30 * time.Second,
		ExecSyncTimeout:  15 * time.Minute,

		otkHandlers:        make([]OTKHandler, 0),
		deviceListHandlers: make([]DeviceListHandler, 0),
	}
}

func (ep *EventProcessor) On(evtType event.Type, handler EventHandler) {
	handlers, ok := ep.handlers[evtType]
	if !ok {
		handlers = []EventHandler{handler}
	} else {
		handlers = append(handlers, handler)
	}
	ep.handlers[evtType] = handlers
}

func (ep *EventProcessor) PrependHandler(evtType event.Type, handler EventHandler) {
	handlers, ok := ep.handlers[evtType]
	if !ok {
		handlers = []EventHandler{handler}
	} else {
		handlers = append([]EventHandler{handler}, handlers...)
	}
	ep.handlers[evtType] = handlers
}

func (ep *EventProcessor) OnOTK(handler OTKHandler) {
	ep.otkHandlers = append(ep.otkHandlers, handler)
}

func (ep *EventProcessor) OnDeviceList(handler DeviceListHandler) {
	ep.deviceListHandlers = append(ep.deviceListHandlers, handler)
}

func (ep *EventProcessor) recoverFunc(data interface{}) {
	if err := recover(); err != nil {
		d, _ := json.Marshal(data)
		ep.as.Log.Error().
			Str(zerolog.ErrorStackFieldName, string(debug.Stack())).
			Interface(zerolog.ErrorFieldName, err).
			Str("event_content", string(d)).
			Msg("Panic in Matrix event handler")
	}
}

func (ep *EventProcessor) callHandler(ctx context.Context, handler EventHandler, evt *event.Event) {
	defer ep.recoverFunc(evt)
	handler(ctx, evt)
}

func (ep *EventProcessor) callOTKHandler(ctx context.Context, handler OTKHandler, otk *mautrix.OTKCount) {
	defer ep.recoverFunc(otk)
	handler(ctx, otk)
}

func (ep *EventProcessor) callDeviceListHandler(ctx context.Context, handler DeviceListHandler, dl *mautrix.DeviceLists) {
	defer ep.recoverFunc(dl)
	handler(ctx, dl, "")
}

func (ep *EventProcessor) DispatchOTK(ctx context.Context, otk *mautrix.OTKCount) {
	for _, handler := range ep.otkHandlers {
		go ep.callOTKHandler(ctx, handler, otk)
	}
}

func (ep *EventProcessor) DispatchDeviceList(ctx context.Context, dl *mautrix.DeviceLists) {
	for _, handler := range ep.deviceListHandlers {
		go ep.callDeviceListHandler(ctx, handler, dl)
	}
}

func (ep *EventProcessor) Dispatch(ctx context.Context, evt *event.Event) {
	handlers, ok := ep.handlers[evt.Type]
	if !ok {
		return
	}
	switch ep.ExecMode {
	case AsyncHandlers:
		for _, handler := range handlers {
			go ep.callHandler(ctx, handler, evt)
		}
	case AsyncLoop:
		go func() {
			for _, handler := range handlers {
				ep.callHandler(ctx, handler, evt)
			}
		}()
	case Sync:
		if ep.ExecSyncWarnTime == 0 && ep.ExecSyncTimeout == 0 {
			for _, handler := range handlers {
				ep.callHandler(ctx, handler, evt)
			}
			return
		}
		doneChan := make(chan struct{})
		go func() {
			for _, handler := range handlers {
				ep.callHandler(ctx, handler, evt)
			}
			close(doneChan)
		}()
		select {
		case <-doneChan:
			return
		case <-time.After(ep.ExecSyncWarnTime):
			log := ep.as.Log.With().
				Str("event_id", evt.ID.String()).
				Str("event_type", evt.Type.String()).
				Logger()
			log.Warn().Msg("Handling event in appservice transaction channel is taking long")
			select {
			case <-doneChan:
				return
			case <-time.After(ep.ExecSyncTimeout):
				log.Error().Msg("Giving up waiting for event handler")
			}
		}
	}
}
func (ep *EventProcessor) startEvents(ctx context.Context) {
	for {
		select {
		case evt := <-ep.as.Events:
			ep.Dispatch(ctx, evt)
		case <-ep.stop:
			return
		}
	}
}

func (ep *EventProcessor) startEncryption(ctx context.Context) {
	for {
		select {
		case evt := <-ep.as.ToDeviceEvents:
			ep.Dispatch(ctx, evt)
		case otk := <-ep.as.OTKCounts:
			ep.DispatchOTK(ctx, otk)
		case dl := <-ep.as.DeviceLists:
			ep.DispatchDeviceList(ctx, dl)
		case <-ep.stop:
			return
		}
	}
}

func (ep *EventProcessor) Start(ctx context.Context) {
	go ep.startEvents(ctx)
	go ep.startEncryption(ctx)
}

func (ep *EventProcessor) Stop() {
	close(ep.stop)
}
