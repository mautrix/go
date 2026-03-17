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

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
)

type BeeperStreamTransport interface {
	BuildDescriptor(ctx context.Context, req *StreamDescriptorRequest) (*event.BeeperStreamInfo, error)
	Start(ctx context.Context, req *StartStreamRequest) error
	Publish(ctx context.Context, req *PublishStreamRequest) error
	Finish(ctx context.Context, req *FinishStreamRequest) error
}

type StreamDescriptorRequest = mautrix.StreamDescriptorRequest
type StartStreamRequest = mautrix.StartStreamRequest
type PublishStreamRequest = mautrix.PublishStreamRequest
type FinishStreamRequest = mautrix.FinishStreamRequest

type matrixConnectorWithStreamGenerator interface {
	MatrixConnector
	GetOrCreateStreamGenerator(ctx context.Context, opts *mautrix.StreamGeneratorOptions) (*mautrix.StreamGenerator, error)
}

type userLoginBeeperStream struct {
	login *UserLogin

	generatorLock sync.Mutex
	generator     *mautrix.StreamGenerator
}

func newUserLoginBeeperStream(login *UserLogin) BeeperStreamTransport {
	return &userLoginBeeperStream{login: login}
}

func (st *userLoginBeeperStream) BuildDescriptor(ctx context.Context, req *StreamDescriptorRequest) (*event.BeeperStreamInfo, error) {
	gen, err := st.getGenerator(ctx)
	if err != nil {
		return nil, err
	}
	return gen.BuildDescriptor(ctx, req)
}

func (st *userLoginBeeperStream) Start(ctx context.Context, req *StartStreamRequest) error {
	gen, err := st.getGenerator(ctx)
	if err != nil {
		return err
	}
	return gen.Start(ctx, req)
}

func (st *userLoginBeeperStream) Publish(ctx context.Context, req *PublishStreamRequest) error {
	gen, err := st.getGenerator(ctx)
	if err != nil {
		return err
	}
	return gen.Publish(ctx, req)
}

func (st *userLoginBeeperStream) Finish(ctx context.Context, req *FinishStreamRequest) error {
	gen, err := st.getGenerator(ctx)
	if err != nil {
		return err
	}
	return gen.Finish(ctx, req)
}

func (st *userLoginBeeperStream) getGenerator(ctx context.Context) (*mautrix.StreamGenerator, error) {
	st.generatorLock.Lock()
	defer st.generatorLock.Unlock()
	if st.generator != nil {
		return st.generator, nil
	}
	conn, ok := st.login.Bridge.Matrix.(matrixConnectorWithStreamGenerator)
	if !ok {
		return nil, fmt.Errorf("matrix connector doesn't support streams")
	}
	var err error
	st.generator, err = conn.GetOrCreateStreamGenerator(ctx, &mautrix.StreamGeneratorOptions{
		AuthorizeSubscriber: st.authorizeSubscriber,
	})
	if err != nil {
		return nil, err
	}
	return st.generator, nil
}

func (st *userLoginBeeperStream) authorizeSubscriber(ctx context.Context, req *mautrix.StreamSubscribeRequest) bool {
	user, err := st.login.Bridge.GetUserByMXID(ctx, req.UserID)
	if err != nil {
		st.login.Log.Err(err).Stringer("sender", req.UserID).Msg("Failed to load stream subscriber user")
		return false
	}
	if user == nil || !user.Permissions.SendEvents {
		return false
	}
	member, err := st.login.Bridge.Matrix.GetMemberInfo(ctx, req.RoomID, req.UserID)
	if err != nil {
		st.login.Log.Err(err).
			Stringer("sender", req.UserID).
			Stringer("room_id", req.RoomID).
			Msg("Failed to load stream subscriber membership")
		return false
	}
	return member != nil && member.Membership == event.MembershipJoin
}
