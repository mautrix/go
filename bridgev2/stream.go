// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"fmt"
	"sync"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/streamhelper"
)

const DefaultStreamExpiry = streamhelper.DefaultStreamExpiry

type BeeperStream interface {
	BuildDescriptor(ctx context.Context, req *StreamDescriptorRequest) (*event.BeeperStreamInfo, error)
	Start(ctx context.Context, req *StartStreamRequest) error
	Publish(ctx context.Context, req *PublishStreamRequest) error
	Finish(ctx context.Context, req *FinishStreamRequest) error
}

type StreamTransport = BeeperStream

type StreamDescriptorRequest = streamhelper.StreamDescriptorRequest
type StartStreamRequest = streamhelper.StartRequest
type PublishStreamRequest = streamhelper.PublishRequest
type FinishStreamRequest = streamhelper.FinishRequest

type matrixConnectorWithStreamHelper interface {
	MatrixConnector
	GetStreamHelper() *streamhelper.Helper
}

type userLoginBeeperStream struct {
	login *UserLogin

	generatorLock sync.Mutex
	generator     *streamhelper.Generator
}

func newUserLoginBeeperStream(login *UserLogin) BeeperStream {
	return &userLoginBeeperStream{login: login}
}

func (st *userLoginBeeperStream) BuildDescriptor(ctx context.Context, req *StreamDescriptorRequest) (*event.BeeperStreamInfo, error) {
	gen, err := st.getGenerator()
	if err != nil {
		return nil, err
	}
	return gen.BuildDescriptor(ctx, req)
}

func (st *userLoginBeeperStream) Start(ctx context.Context, req *StartStreamRequest) error {
	gen, err := st.getGenerator()
	if err != nil {
		return err
	}
	return gen.Start(ctx, req)
}

func (st *userLoginBeeperStream) Publish(ctx context.Context, req *PublishStreamRequest) error {
	gen, err := st.getGenerator()
	if err != nil {
		return err
	}
	return gen.Publish(ctx, req)
}

func (st *userLoginBeeperStream) Finish(ctx context.Context, req *FinishStreamRequest) error {
	gen, err := st.getGenerator()
	if err != nil {
		return err
	}
	return gen.Finish(ctx, req)
}

func (st *userLoginBeeperStream) getGenerator() (*streamhelper.Generator, error) {
	st.generatorLock.Lock()
	defer st.generatorLock.Unlock()
	if st.generator != nil {
		return st.generator, nil
	}
	conn, ok := st.login.Bridge.Matrix.(matrixConnectorWithStreamHelper)
	if !ok {
		return nil, fmt.Errorf("matrix connector doesn't support streams")
	}
	helper := conn.GetStreamHelper()
	if helper == nil {
		return nil, fmt.Errorf("stream helper isn't initialized")
	}
	st.generator = helper.NewGenerator(&streamhelper.GeneratorOptions{
		AuthorizeSubscriber: st.authorizeSubscriber,
	})
	return st.generator, nil
}

func (st *userLoginBeeperStream) authorizeSubscriber(ctx context.Context, sender id.UserID) bool {
	user, err := st.login.Bridge.GetUserByMXID(ctx, sender)
	if err != nil {
		st.login.Log.Err(err).Str("sender", sender.String()).Msg("Failed to load stream subscriber user")
		return false
	}
	return user != nil && user.Permissions.SendEvents
}
