// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package federation

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
)

// ResolutionCache is an interface for caching resolved server names.
type ResolutionCache interface {
	StoreResolution(context.Context, *ResolvedServerName) error
	// LoadResolution loads a resolved server name from the cache.
	// Expired entries MUST NOT be returned.
	LoadResolution(ctx context.Context, serverName string) (*ResolvedServerName, error)
}

type KeyCache interface {
	StoreKeys(context.Context, *ServerKeyResponse) error
	StoreFetchError(ctx context.Context, serverName string, err error)
	ShouldReQuery(ctx context.Context, serverName string) (bool, error)
	LoadKeys(ctx context.Context, serverName string) (*ServerKeyResponse, error)
}

type InMemoryCache struct {
	MinKeyRefetchDelay time.Duration

	resolutions     map[string]*ResolvedServerName
	resolutionsLock sync.RWMutex
	keys            map[string]*ServerKeyResponse
	lastReQueryAt   map[string]time.Time
	lastError       map[string]*resolutionErrorCache
	keysLock        sync.RWMutex
}

var (
	_ ResolutionCache = (*InMemoryCache)(nil)
	_ KeyCache        = (*InMemoryCache)(nil)
)

func NewInMemoryCache() *InMemoryCache {
	return &InMemoryCache{
		resolutions:        make(map[string]*ResolvedServerName),
		keys:               make(map[string]*ServerKeyResponse),
		lastReQueryAt:      make(map[string]time.Time),
		lastError:          make(map[string]*resolutionErrorCache),
		MinKeyRefetchDelay: 1 * time.Hour,
	}
}

func (c *InMemoryCache) StoreResolution(_ context.Context, resolution *ResolvedServerName) error {
	c.resolutionsLock.Lock()
	defer c.resolutionsLock.Unlock()
	c.resolutions[resolution.ServerName] = resolution
	return nil
}

func (c *InMemoryCache) LoadResolution(_ context.Context, serverName string) (*ResolvedServerName, error) {
	c.resolutionsLock.RLock()
	defer c.resolutionsLock.RUnlock()
	resolution, ok := c.resolutions[serverName]
	if !ok || time.Until(resolution.Expires) < 0 {
		return nil, nil
	}
	return resolution, nil
}

func (c *InMemoryCache) StoreKeys(_ context.Context, keys *ServerKeyResponse) error {
	c.keysLock.Lock()
	defer c.keysLock.Unlock()
	c.keys[keys.ServerName] = keys
	delete(c.lastError, keys.ServerName)
	return nil
}

type resolutionErrorCache struct {
	Error error
	Time  time.Time
	Count int
}

const MaxBackoff = 7 * 24 * time.Hour

func (rec *resolutionErrorCache) ShouldRetry() bool {
	backoff := time.Duration(math.Exp(float64(rec.Count))) * time.Second
	return time.Since(rec.Time) > backoff
}

var ErrRecentKeyQueryFailed = errors.New("last retry was too recent")

func (c *InMemoryCache) LoadKeys(_ context.Context, serverName string) (*ServerKeyResponse, error) {
	c.keysLock.RLock()
	defer c.keysLock.RUnlock()
	keys, ok := c.keys[serverName]
	if !ok || time.Until(keys.ValidUntilTS.Time) < 0 {
		err, ok := c.lastError[serverName]
		if ok && !err.ShouldRetry() {
			return nil, fmt.Errorf(
				"%w (%s ago) and failed with %w",
				ErrRecentKeyQueryFailed,
				time.Since(err.Time).String(),
				err.Error,
			)
		}
		return nil, nil
	}
	return keys, nil
}

func (c *InMemoryCache) StoreFetchError(_ context.Context, serverName string, err error) {
	c.keysLock.Lock()
	defer c.keysLock.Unlock()
	errorCache, ok := c.lastError[serverName]
	if ok {
		errorCache.Time = time.Now()
		errorCache.Error = err
		errorCache.Count++
	} else {
		c.lastError[serverName] = &resolutionErrorCache{Error: err, Time: time.Now(), Count: 1}
	}
}

func (c *InMemoryCache) ShouldReQuery(_ context.Context, serverName string) (bool, error) {
	c.keysLock.Lock()
	defer c.keysLock.Unlock()
	lastQuery, ok := c.lastReQueryAt[serverName]
	if ok && time.Since(lastQuery) < c.MinKeyRefetchDelay {
		return false, nil
	}
	c.lastReQueryAt[serverName] = time.Now()
	return true, nil
}

type noopCache struct{}

func (*noopCache) StoreKeys(_ context.Context, _ *ServerKeyResponse) error          { return nil }
func (*noopCache) LoadKeys(_ context.Context, _ string) (*ServerKeyResponse, error) { return nil, nil }
func (*noopCache) StoreFetchError(_ context.Context, _ string, _ error)             {}
func (*noopCache) ShouldReQuery(_ context.Context, _ string) (bool, error)          { return true, nil }
func (*noopCache) StoreResolution(_ context.Context, _ *ResolvedServerName) error   { return nil }
func (*noopCache) LoadResolution(_ context.Context, _ string) (*ResolvedServerName, error) {
	return nil, nil
}

var (
	_ ResolutionCache = (*noopCache)(nil)
	_ KeyCache        = (*noopCache)(nil)
)

var NoopCache *noopCache
