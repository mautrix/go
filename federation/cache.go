// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package federation

import (
	"sync"
	"time"
)

// ResolutionCache is an interface for caching resolved server names.
type ResolutionCache interface {
	StoreResolution(*ResolvedServerName)
	// LoadResolution loads a resolved server name from the cache.
	// Expired entries MUST NOT be returned.
	LoadResolution(serverName string) (*ResolvedServerName, error)
}

type KeyCache interface {
	StoreKeys(*ServerKeyResponse)
	LoadKeys(serverName string) (*ServerKeyResponse, error)
}

type InMemoryCache struct {
	resolutions     map[string]*ResolvedServerName
	resolutionsLock sync.RWMutex
	keys            map[string]*ServerKeyResponse
	keysLock        sync.RWMutex
}

func NewInMemoryCache() *InMemoryCache {
	return &InMemoryCache{
		resolutions: make(map[string]*ResolvedServerName),
		keys:        make(map[string]*ServerKeyResponse),
	}
}

func (c *InMemoryCache) StoreResolution(resolution *ResolvedServerName) {
	c.resolutionsLock.Lock()
	defer c.resolutionsLock.Unlock()
	c.resolutions[resolution.ServerName] = resolution
}

func (c *InMemoryCache) LoadResolution(serverName string) (*ResolvedServerName, error) {
	c.resolutionsLock.RLock()
	defer c.resolutionsLock.RUnlock()
	resolution, ok := c.resolutions[serverName]
	if !ok || time.Until(resolution.Expires) < 0 {
		return nil, nil
	}
	return resolution, nil
}

func (c *InMemoryCache) StoreKeys(keys *ServerKeyResponse) {
	c.keysLock.Lock()
	defer c.keysLock.Unlock()
	c.keys[keys.ServerName] = keys
}

func (c *InMemoryCache) LoadKeys(serverName string) (*ServerKeyResponse, error) {
	c.keysLock.RLock()
	defer c.keysLock.RUnlock()
	keys, ok := c.keys[serverName]
	if !ok || time.Until(keys.ValidUntilTS.Time) < 0 {
		return nil, nil
	}
	return keys, nil
}
