// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package util_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"maunium.net/go/mautrix/util"
)

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		input    time.Duration
		expected string
	}{
		{0, "now"},
		{500 * time.Millisecond, "now"},
		{999*time.Millisecond + 999*time.Microsecond + 999*time.Nanosecond, "now"},
		{999*time.Millisecond + 999*time.Microsecond + 999*time.Nanosecond + 1, "1 second"},
		{time.Second, "1 second"},
		{2 * time.Second, "2 seconds"},
		{59 * time.Second, "59 seconds"},
		{time.Minute, "1 minute"},
		{2 * time.Minute, "2 minutes"},
		{time.Hour, "1 hour"},
		{2 * time.Hour, "2 hours"},
		{util.Day, "1 day"},
		{2 * util.Day, "2 days"},
		{util.Week, "1 week"},
		{2 * util.Week, "2 weeks"},
		{8 * util.Day, "1 week and 1 day"},
		{16 * util.Day, "2 weeks and 2 days"},
		{time.Minute + time.Second, "1 minute and 1 second"},
		{2*time.Minute + 2*time.Second, "2 minutes and 2 seconds"},
		{time.Hour + time.Second, "1 hour and 1 second"},
		{2*time.Hour + 2*time.Second, "2 hours and 2 seconds"},
		{2*time.Hour + time.Minute, "2 hours and 1 minute"},
		{time.Hour + time.Minute + time.Second, "1 hour, 1 minute and 1 second"},
		{2*time.Hour + 2*time.Minute + 2*time.Second, "2 hours, 2 minutes and 2 seconds"},
		{987654 * time.Second, "1 week, 4 days, 10 hours, 20 minutes and 54 seconds"},
		{694861 * time.Second, "1 week, 1 day, 1 hour, 1 minute and 1 second"},
		{1234 * time.Second, "20 minutes and 34 seconds"},
	}

	for _, test := range tests {
		assert.Equal(t, test.expected, util.FormatDuration(test.input))
	}
}

func TestFormatDuration_PanicNegative(t *testing.T) {
	assert.Panics(t, func() { util.FormatDuration(-1) })
	assert.Panics(t, func() { util.FormatDuration(-time.Second) })
	assert.Panics(t, func() { util.FormatDuration(-util.Week) })
}
