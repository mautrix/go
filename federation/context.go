// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package federation

import (
	"context"
	"net/http"
)

type contextKey int

const (
	contextKeyIPPort contextKey = iota
	contextKeyDestinationServer
)

func DestinationServerNameFromRequest(r *http.Request) string {
	return DestinationServerName(r.Context())
}

func DestinationServerName(ctx context.Context) string {
	if dest, ok := ctx.Value(contextKeyDestinationServer).(string); ok {
		return dest
	}
	return ""
}
