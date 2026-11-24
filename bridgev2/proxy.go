// Copyright (c) 2026 Nick Mills-Barrett
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"maunium.net/go/mautrix"
)

var proxyLookupClient = &http.Client{Timeout: 30 * time.Second}

// GetProxy returns the proxy URL to use for remote network connections, or an empty string if no proxy is configured.
// If a lookup URL is configured, it is requested with the given reason and must return a non-empty proxy URL.
func (br *Bridge) GetProxy(ctx context.Context, reason string) (string, error) {
	if br.Config.Proxy.LookupURL == "" {
		return br.Config.Proxy.URL, nil
	}
	// Errors must not include the lookup URL, as it may contain a token.
	parsed, err := url.Parse(br.Config.Proxy.LookupURL)
	if err != nil {
		return "", errors.New("failed to parse proxy lookup URL")
	}
	q := parsed.Query()
	q.Set("reason", reason)
	parsed.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return "", errors.New("failed to prepare proxy lookup request")
	}
	req.Header.Set("User-Agent", mautrix.DefaultUserAgent)
	resp, err := proxyLookupClient.Do(req)
	if err != nil {
		if urlErr, ok := errors.AsType[*url.Error](err); ok {
			err = urlErr.Err
		}
		return "", fmt.Errorf("failed to send proxy lookup request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("unexpected status code %d from proxy lookup", resp.StatusCode)
	}
	var respData struct {
		ProxyURL string `json:"proxy_url"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return "", fmt.Errorf("failed to decode proxy lookup response: %w", err)
	} else if respData.ProxyURL == "" {
		return "", errors.New("proxy lookup returned an empty proxy URL")
	}
	return respData.ProxyURL, nil
}
