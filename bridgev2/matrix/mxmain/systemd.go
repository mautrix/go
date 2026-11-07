// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mxmain

import (
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/rs/zerolog"
)

// sdNotifyReady tells the systemd service manager that the bridge has finished
// starting up. The call is a no-op when the bridge is not running under a
// systemd unit with `Type=notify`.
//
// See https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html.
func sdNotifyReady(log *zerolog.Logger) {
	if sent, err := daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
		log.Warn().Err(err).Msg("Failed to send systemd READY=1 notification")
	} else if sent {
		log.Debug().Msg("Sent systemd READY=1 notification")
	}
}

// sdNotifyStopping tells the systemd service manager that the bridge is
// shutting down. The call is a no-op outside of systemd.
func sdNotifyStopping(log *zerolog.Logger) {
	if sent, err := daemon.SdNotify(false, daemon.SdNotifyStopping); err != nil {
		log.Warn().Err(err).Msg("Failed to send systemd STOPPING=1 notification")
	} else if sent {
		log.Debug().Msg("Sent systemd STOPPING=1 notification")
	}
}

// startSdWatchdog pings the systemd watchdog at half the configured interval
// for as long as the returned stop function has not been called. The returned
// stop function blocks until the watchdog goroutine has exited.
//
// Returns a no-op stop function when the process is not running under a
// systemd unit with `WatchdogSec=` set (so the call is always safe).
func startSdWatchdog(log *zerolog.Logger) (stop func()) {
	interval, err := daemon.SdWatchdogEnabled(false)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to query systemd watchdog setting")
		return func() {}
	}
	if interval == 0 {
		// No watchdog configured by the unit file.
		return func() {}
	}
	// systemd recommends pinging at half the configured interval to leave
	// headroom for scheduling jitter.
	ping := interval / 2
	log.Info().
		Stringer("watchdog_interval", interval).
		Stringer("ping_interval", ping).
		Msg("Starting systemd watchdog pinger")

	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(ping)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if _, err := daemon.SdNotify(false, daemon.SdNotifyWatchdog); err != nil {
					log.Warn().Err(err).Msg("Failed to send systemd WATCHDOG=1 notification")
				}
			}
		}
	}()
	return func() {
		close(done)
		<-stopped
	}
}
