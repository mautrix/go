// Copyright (c) 2021 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package appservice

import "sync"

type TransactionIDCache struct {
	array    []string
	arrayPtr int
	hash     map[string]struct{}
	lock     sync.RWMutex
}

func NewTransactionIDCache(size int) *TransactionIDCache {
	return &TransactionIDCache{
		array: make([]string, size),
		hash:  make(map[string]struct{}),
	}
}

func (txnIDC *TransactionIDCache) IsProcessed(txnID string) bool {
	txnIDC.lock.RLock()
	_, exists := txnIDC.hash[txnID]
	txnIDC.lock.RUnlock()
	return exists
}

func (txnIDC *TransactionIDCache) MarkProcessed(txnID string) {
	txnIDC.lock.Lock()
	defer txnIDC.lock.Unlock()
	if _, exists := txnIDC.hash[txnID]; exists || txnID == "" {
		return
	}
	if txnIDC.array[txnIDC.arrayPtr] != "" {
		for i := 0; i < min(max(len(txnIDC.array)/8, 1), len(txnIDC.array)-txnIDC.arrayPtr); i++ {
			delete(txnIDC.hash, txnIDC.array[txnIDC.arrayPtr+i])
			txnIDC.array[txnIDC.arrayPtr+i] = ""
		}
	}
	txnIDC.hash[txnID] = struct{}{}
	txnIDC.array[txnIDC.arrayPtr] = txnID
	txnIDC.arrayPtr = (txnIDC.arrayPtr + 1) % len(txnIDC.array)
}
