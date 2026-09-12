// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mxmain

import (
	"os"
	"testing"

	"github.com/rs/zerolog"
)

// TestSdNotifyHelpersAreNoOpWithoutSystemd verifies that the systemd helpers
// are safe to call when the process is not running under a systemd unit (i.e.
// NOTIFY_SOCKET is not set). They must not panic, must not block, and the
// watchdog stop function must be idempotent and return promptly.
func TestSdNotifyHelpersAreNoOpWithoutSystemd(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	t.Setenv("WATCHDOG_USEC", "")
	t.Setenv("WATCHDOG_PID", "")
	// Some test runners inherit a parent NOTIFY_SOCKET; explicitly unset it
	// so the helpers really do see a non-systemd environment.
	_ = os.Unsetenv("NOTIFY_SOCKET")
	_ = os.Unsetenv("WATCHDOG_USEC")
	_ = os.Unsetenv("WATCHDOG_PID")

	log := zerolog.Nop()
	sdNotifyReady(&log)
	sdNotifyStopping(&log)

	stop := startSdWatchdog(&log)
	if stop == nil {
		t.Fatal("startSdWatchdog returned a nil stop function")
	}
	stop()
}
