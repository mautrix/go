// Copyright (c) 2026 Beeper
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/rs/xid"
	"go.mau.fi/util/exhttp"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
)

const clientStreamBufferSize = 4 * bridgev2.LoginClientStreamMaxChunkSize

type loginClientStream struct {
	ctx          context.Context
	lock         sync.Mutex
	writeLock    sync.Mutex
	changed      chan struct{}
	incoming     bytes.Buffer
	received     uint64
	lastReceived *bridgev2.LoginClientStreamPacket
	sent         uint64
	acked        uint64
	outgoing     *bridgev2.LoginClientStreamPacket
	closed       bool
	err          error
	terminal     bridgev2.LoginClientStreamPacket
	stopCancel   func() bool
	idleTimer    *time.Timer
	idleDeadline time.Time
}

var _ io.ReadWriteCloser = (*loginClientStream)(nil)

func (p *ProvLogin) newClientStream() (string, *loginClientStream, error) {
	p.streamsLock.Lock()
	defer p.streamsLock.Unlock()
	if p.Ctx.Err() != nil {
		return "", nil, p.Ctx.Err()
	}
	// Closed streams remain addressable for retries until the login ends.
	if len(p.streams) >= 8 {
		return "", nil, fmt.Errorf("too many client WebSocket streams in one login")
	}
	if p.streams == nil {
		p.streams = make(map[string]*loginClientStream)
	}
	s := &loginClientStream{ctx: p.Ctx, changed: make(chan struct{})}
	s.idleDeadline = time.Now().Add(time.Minute)
	s.idleTimer = time.AfterFunc(time.Minute, s.checkIdle)
	s.stopCancel = context.AfterFunc(p.Ctx, func() { s.closeWithError(p.Ctx.Err()) })
	streamID := xid.New().String()
	p.streams[streamID] = s
	return streamID, s, nil
}

func (s *loginClientStream) notifyLocked() {
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *loginClientStream) checkIdle() {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.closed {
		return
	}
	if remaining := time.Until(s.idleDeadline); remaining > 0 {
		s.idleTimer.Reset(remaining)
	} else {
		s.closeLocked(fmt.Errorf("client stream relay timed out"))
	}
}

func (s *loginClientStream) closeLocked(err error) {
	if s.closed {
		return
	}
	s.closed = true
	s.idleTimer.Stop()
	s.err = err
	s.terminal = bridgev2.LoginClientStreamPacket{Sequence: s.sent + 1, Closed: true}
	if err != nil && !errors.Is(err, io.EOF) {
		s.terminal.Error = "Client WebSocket stream closed"
	}
	s.notifyLocked()
}

func (s *loginClientStream) closeWithError(err error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.closeLocked(err)
}

func (s *loginClientStream) Close() error {
	s.closeWithError(io.EOF)
	if s.stopCancel != nil {
		s.stopCancel()
	}
	return nil
}

func (s *loginClientStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	for {
		if s.incoming.Len() > 0 {
			n, err := s.incoming.Read(p)
			s.notifyLocked()
			return n, err
		}
		if s.closed {
			if s.err != nil {
				return 0, s.err
			}
			return 0, io.EOF
		}
		changed := s.changed
		s.lock.Unlock()
		<-changed
		s.lock.Lock()
	}
}

func (s *loginClientStream) Write(data []byte) (int, error) {
	s.writeLock.Lock()
	defer s.writeLock.Unlock()
	written := 0
	for len(data) > 0 {
		chunk := data[:min(len(data), bridgev2.LoginClientStreamMaxChunkSize)]
		s.lock.Lock()
		if s.closed {
			s.lock.Unlock()
			return written, io.ErrClosedPipe
		}
		s.sent++
		sequence := s.sent
		s.outgoing = &bridgev2.LoginClientStreamPacket{Sequence: sequence, Data: bytes.Clone(chunk)}
		s.notifyLocked()
		for s.acked < sequence && !s.closed {
			changed := s.changed
			s.lock.Unlock()
			<-changed
			s.lock.Lock()
		}
		acked := s.acked >= sequence
		s.lock.Unlock()
		if !acked {
			return written, io.ErrClosedPipe
		}
		written += len(chunk)
		data = data[len(chunk):]
	}
	return written, nil
}

func (s *loginClientStream) poll(ctx context.Context) (*bridgev2.LoginClientStreamPacket, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	s.lock.Lock()
	defer s.lock.Unlock()
	if !s.closed {
		s.idleDeadline = time.Now().Add(time.Minute)
		s.idleTimer.Reset(time.Minute)
	}
	for {
		if s.closed {
			packet := s.terminal
			return &packet, nil
		}
		if s.outgoing != nil {
			packet := *s.outgoing
			return &packet, nil
		}
		changed := s.changed
		s.lock.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
		}
		s.lock.Lock()
		if ctx.Err() != nil {
			return &bridgev2.LoginClientStreamPacket{}, nil
		}
	}
}

func (s *loginClientStream) exchange(ctx context.Context, req *bridgev2.LoginClientStreamExchange) (uint64, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if !s.closed {
		s.idleDeadline = time.Now().Add(time.Minute)
		s.idleTimer.Reset(time.Minute)
	}
	if req.Ack > s.sent {
		// The final close packet has no bytes to commit.
		if !s.closed || req.Ack != s.terminal.Sequence {
			return s.received, mautrix.MBadJSON.WithMessage("Invalid stream acknowledgement")
		}
	} else if req.Ack > s.acked {
		s.acked = req.Ack
		s.outgoing = nil
		s.notifyLocked()
	}
	p := req.Packet
	if p == nil {
		return s.received, nil
	}
	if p.Sequence == 0 || len(p.Data) > bridgev2.LoginClientStreamMaxChunkSize || len(p.Error) > 300 ||
		(p.Error != "" && !p.Closed) || (len(p.Data) == 0 && !p.Closed) {
		return s.received, mautrix.MBadJSON.WithMessage("Invalid stream packet")
	}
	for {
		if p.Sequence <= s.received {
			if p.Sequence == s.received && (p.Closed != s.lastReceived.Closed || p.Error != s.lastReceived.Error || !bytes.Equal(p.Data, s.lastReceived.Data)) {
				return s.received, mautrix.MBadJSON.WithMessage("Conflicting stream packet retry")
			}
			return s.received, nil
		}
		if p.Sequence != s.received+1 {
			return s.received, mautrix.MBadJSON.WithMessage("Stream packet sequence gap")
		}
		if s.closed {
			return s.received, mautrix.MBadState.WithMessage("Stream is closed")
		}
		if s.incoming.Len()+len(p.Data) <= clientStreamBufferSize {
			break
		}
		changed := s.changed
		s.lock.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
		}
		s.lock.Lock()
		if ctx.Err() != nil {
			return s.received, ctx.Err()
		}
	}
	s.incoming.Write(p.Data)
	s.received = p.Sequence
	packet := *p
	packet.Data = bytes.Clone(p.Data)
	s.lastReceived = &packet
	if p.Closed {
		if p.Error != "" {
			s.closeLocked(fmt.Errorf("%s%s", ErrorFromClientPrefix, p.Error))
		} else {
			s.closeLocked(io.EOF)
		}
	}
	s.notifyLocked()
	return s.received, nil
}

func (prov *ProvisioningAPI) getLoginClientStream(w http.ResponseWriter, r *http.Request) *loginClientStream {
	prov.loginsLock.RLock()
	login := prov.logins[r.PathValue("loginProcessID")]
	prov.loginsLock.RUnlock()
	if login == nil || login.UserMXID != prov.GetUser(r).MXID {
		mautrix.MNotFound.WithMessage("Login not found").Write(w)
		return nil
	}
	login.streamsLock.Lock()
	stream := login.streams[r.PathValue("streamID")]
	login.streamsLock.Unlock()
	if stream == nil {
		mautrix.MNotFound.WithMessage("Stream not found").Write(w)
	}
	return stream
}

func (prov *ProvisioningAPI) GetLoginClientStream(w http.ResponseWriter, r *http.Request) {
	stream := prov.getLoginClientStream(w, r)
	if stream == nil {
		return
	}
	packet, err := stream.poll(r.Context())
	if err != nil {
		RespondWithError(w, err, "Failed to poll client stream")
		return
	}
	exhttp.WriteJSONResponse(w, http.StatusOK, packet)
}

func (prov *ProvisioningAPI) PostLoginClientStream(w http.ResponseWriter, r *http.Request) {
	stream := prov.getLoginClientStream(w, r)
	if stream == nil {
		return
	}
	// Authentication middleware installs a smaller default limit.
	body := r.Body
	if r.GetBody != nil {
		var err error
		body, err = r.GetBody()
		if err != nil {
			RespondWithError(w, err, "Failed to read client stream exchange")
			return
		}
	}
	defer body.Close()
	var req bridgev2.LoginClientStreamExchange
	err := json.NewDecoder(http.MaxBytesReader(w, body, 128*1024)).Decode(&req)
	if err != nil {
		mautrix.MBadJSON.WithMessage("Invalid stream exchange").Write(w)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	ack, err := stream.exchange(ctx, &req)
	if err != nil {
		RespondWithError(w, err, "Failed to exchange client stream data")
		return
	}
	exhttp.WriteJSONResponse(w, http.StatusOK, &bridgev2.LoginClientStreamExchangeResponse{Ack: ack})
}
