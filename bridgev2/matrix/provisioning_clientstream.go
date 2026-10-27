// Copyright (c) 2026 Beeper
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/rs/xid"

	"maunium.net/go/mautrix"
)

type loginClientStream struct {
	ctx     context.Context
	cancel  context.CancelFunc
	lock    sync.Mutex
	ready   chan struct{}
	done    chan struct{}
	conn    net.Conn
	claimed bool
	closed  bool
	opening *time.Timer
}

var _ io.ReadWriteCloser = (*loginClientStream)(nil)

func (p *ProvLogin) newClientStream() (string, *loginClientStream, error) {
	p.streamsLock.Lock()
	defer p.streamsLock.Unlock()
	if p.Ctx.Err() != nil {
		return "", nil, p.Ctx.Err()
	}
	if len(p.streams) >= 8 {
		return "", nil, fmt.Errorf("too many client WebSocket streams in one login")
	}
	if p.streams == nil {
		p.streams = make(map[string]*loginClientStream)
	}
	ctx, cancel := context.WithCancel(p.Ctx)
	s := &loginClientStream{ctx: ctx, cancel: cancel, ready: make(chan struct{}), done: make(chan struct{})}
	s.opening = time.AfterFunc(time.Minute, func() { _ = s.Close() })
	context.AfterFunc(ctx, func() { _ = s.Close() })
	id := xid.New().String()
	p.streams[id] = s
	return id, s, nil
}

func (s *loginClientStream) waitConn(ctx context.Context) (net.Conn, error) {
	select {
	case <-s.ready:
	case <-s.done:
		return nil, io.ErrClosedPipe
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.closed {
		return nil, io.ErrClosedPipe
	}
	return s.conn, nil
}

func (s *loginClientStream) Read(buf []byte) (int, error) {
	conn, err := s.waitConn(s.ctx)
	if err != nil {
		return 0, err
	}
	n, err := conn.Read(buf)
	if err != nil {
		_ = s.Close()
	}
	return n, err
}

func (s *loginClientStream) Write(buf []byte) (int, error) {
	conn, err := s.waitConn(s.ctx)
	if err != nil {
		return 0, err
	}
	n, err := conn.Write(buf)
	if err != nil {
		_ = s.Close()
	}
	return n, err
}

func (s *loginClientStream) Close() error {
	s.lock.Lock()
	if s.closed {
		s.lock.Unlock()
		return nil
	}
	s.closed = true
	s.opening.Stop()
	conn := s.conn
	close(s.done)
	s.lock.Unlock()
	s.cancel()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func (prov *ProvisioningAPI) GetLoginClientWebSocket(w http.ResponseWriter, r *http.Request) {
	prov.loginsLock.RLock()
	login := prov.logins[r.PathValue("loginProcessID")]
	prov.loginsLock.RUnlock()
	if login == nil || login.UserMXID != prov.GetUser(r).MXID {
		mautrix.MNotFound.WithMessage("Login not found").Write(w)
		return
	}
	login.streamsLock.Lock()
	s := login.streams[r.PathValue("streamID")]
	login.streamsLock.Unlock()
	if s == nil {
		mautrix.MNotFound.WithMessage("Stream not found").Write(w)
		return
	}
	s.lock.Lock()
	if s.claimed || s.closed {
		s.lock.Unlock()
		mautrix.MBadState.WithMessage("Stream cannot be attached again").Write(w)
		return
	}
	s.claimed = true
	s.lock.Unlock()
	defer s.Close()
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer ws.CloseNow()
	conn := websocket.NetConn(s.ctx, ws, websocket.MessageBinary)
	s.lock.Lock()
	if s.closed {
		s.lock.Unlock()
		_ = conn.Close()
		return
	}
	s.conn = conn
	close(s.ready)
	s.lock.Unlock()
	<-s.done
}
