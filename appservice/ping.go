// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package appservice

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix"
)

func (intent *IntentAPI) EnsureAppserviceConnection(ctx context.Context) {
	var pingResp *mautrix.RespAppservicePing
	var txnID string
	var retryCount int
	var err error
	const maxRetries = 6
	for {
		txnID = intent.TxnID()
		pingResp, err = intent.AppservicePing(ctx, intent.as.Registration.ID, txnID)
		if err == nil {
			break
		}
		var httpErr mautrix.HTTPError
		var pingErrBody string
		if errors.As(err, &httpErr) && httpErr.RespError != nil {
			if val, ok := httpErr.RespError.ExtraData["body"].(string); ok {
				pingErrBody = strings.TrimSpace(val)
			}
		}
		outOfRetries := retryCount >= maxRetries
		level := zerolog.ErrorLevel
		if outOfRetries {
			level = zerolog.FatalLevel
		}
		evt := zerolog.Ctx(ctx).WithLevel(level).Err(err).Str("txn_id", txnID)
		if pingErrBody != "" {
			bodyBytes := []byte(pingErrBody)
			if json.Valid(bodyBytes) {
				evt.RawJSON("body", bodyBytes)
			} else {
				evt.Str("body", pingErrBody)
			}
		}
		if outOfRetries {
			evt.Msg("Homeserver -> appservice connection is not working")
			zerolog.Ctx(ctx).Info().Msg("See https://docs.mau.fi/faq/as-ping for more info")
			os.Exit(13)
		}
		evt.Msg("Homeserver -> appservice connection is not working, retrying in 5 seconds...")
		time.Sleep(5 * time.Second)
		retryCount++
	}
	zerolog.Ctx(ctx).Debug().
		Str("txn_id", txnID).
		Int64("duration_ms", pingResp.DurationMS).
		Msg("Homeserver -> appservice connection works")
}
