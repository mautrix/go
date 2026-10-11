// Copyright (c) 2026 gchahcg
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRetryBackoff(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	rb := newRetryBackoff(time.Minute)
	rb.now = func() time.Time { return now }

	assert.False(t, rb.ShouldSkip("@a:example.com"), "nothing has failed yet")

	rb.RecordFailure("@a:example.com")
	assert.True(t, rb.ShouldSkip("@a:example.com"), "should skip right after a failure")
	assert.False(t, rb.ShouldSkip("@b:example.com"), "other users are unaffected")

	now = now.Add(59 * time.Second)
	assert.True(t, rb.ShouldSkip("@a:example.com"), "should still skip inside the delay")

	now = now.Add(2 * time.Second)
	assert.False(t, rb.ShouldSkip("@a:example.com"), "should retry once the delay has passed")
	assert.False(t, rb.ShouldSkip("@a:example.com"), "an expired failure is forgotten")

	rb.RecordFailure("@a:example.com")
	rb.Clear("@a:example.com")
	assert.False(t, rb.ShouldSkip("@a:example.com"), "clearing ends the backoff")
}
