// Copyright (c) 2026 gchahcg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"sync"
	"time"

	"maunium.net/go/mautrix/id"
)

// retryBackoff remembers recent failures per user, so that an operation that keeps failing
// (e.g. because the homeserver doesn't support it) isn't retried on every call.
type retryBackoff struct {
	delay  time.Duration
	failed sync.Map
	now    func() time.Time
}

func newRetryBackoff(delay time.Duration) *retryBackoff {
	return &retryBackoff{delay: delay, now: time.Now}
}

// ShouldSkip returns true if the operation for the given user failed less than the backoff delay ago.
func (rb *retryBackoff) ShouldSkip(userID id.UserID) bool {
	failedAt, ok := rb.failed.Load(userID)
	if !ok {
		return false
	}
	if rb.now().Sub(failedAt.(time.Time)) < rb.delay {
		return true
	}
	rb.failed.Delete(userID)
	return false
}

// RecordFailure starts the backoff period for the given user.
func (rb *retryBackoff) RecordFailure(userID id.UserID) {
	rb.failed.Store(userID, rb.now())
}

// Clear ends the backoff period for the given user.
func (rb *retryBackoff) Clear(userID id.UserID) {
	rb.failed.Delete(userID)
}
