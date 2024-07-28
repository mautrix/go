// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package federation

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// ServerResolvingTransport is an http.RoundTripper that resolves Matrix server names before sending requests.
// It only allows requests using the "matrix-federation" scheme.
type ServerResolvingTransport struct {
	ResolveOpts *ResolveServerNameOpts
	Transport   *http.Transport
	Dialer      *net.Dialer

	cache        map[string]*ResolvedServerName
	resolveLocks map[string]*sync.Mutex
	cacheLock    sync.Mutex
}

func NewServerResolvingTransport() *ServerResolvingTransport {
	srt := &ServerResolvingTransport{
		cache:        make(map[string]*ResolvedServerName),
		resolveLocks: make(map[string]*sync.Mutex),

		Dialer: &net.Dialer{},
	}
	srt.Transport = &http.Transport{
		DialContext: srt.DialContext,
	}
	return srt
}

var _ http.RoundTripper = (*ServerResolvingTransport)(nil)

func (srt *ServerResolvingTransport) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	addrs, ok := ctx.Value(contextKeyIPPort).([]string)
	if !ok {
		return nil, fmt.Errorf("no IP:port in context")
	}
	return srt.Dialer.DialContext(ctx, network, addrs[0])
}

type contextKey int

const (
	contextKeyIPPort contextKey = iota
)

func (srt *ServerResolvingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "matrix-federation" {
		return nil, fmt.Errorf("unsupported scheme: %s", request.URL.Scheme)
	}
	resolved, err := srt.resolve(request.Context(), request.URL.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve server name: %w", err)
	}
	request = request.WithContext(context.WithValue(request.Context(), contextKeyIPPort, resolved.IPPort))
	request.URL.Scheme = "https"
	request.URL.Host = resolved.HostHeader
	request.Host = resolved.HostHeader
	return srt.Transport.RoundTrip(request)
}

func (srt *ServerResolvingTransport) resolve(ctx context.Context, serverName string) (*ResolvedServerName, error) {
	res, lock := srt.getResolveCache(serverName)
	if res != nil {
		return res, nil
	}
	lock.Lock()
	defer lock.Unlock()
	res, _ = srt.getResolveCache(serverName)
	if res != nil {
		return res, nil
	}
	var err error
	res, err = ResolveServerName(ctx, serverName, srt.ResolveOpts)
	if err != nil {
		return nil, err
	}
	srt.cacheLock.Lock()
	srt.cache[serverName] = res
	srt.cacheLock.Unlock()
	return res, nil
}

func (srt *ServerResolvingTransport) getResolveCache(serverName string) (*ResolvedServerName, *sync.Mutex) {
	srt.cacheLock.Lock()
	defer srt.cacheLock.Unlock()
	if val, ok := srt.cache[serverName]; ok && time.Until(val.Expires) > 0 {
		return val, nil
	}
	rl, ok := srt.resolveLocks[serverName]
	if !ok {
		rl = &sync.Mutex{}
		srt.resolveLocks[serverName] = rl
	}
	return nil, rl
}
