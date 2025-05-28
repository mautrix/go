// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package federation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

type ResolvedServerName struct {
	ServerName string    `json:"server_name"`
	HostHeader string    `json:"host_header"`
	IPPort     []string  `json:"ip_port"`
	Expires    time.Time `json:"expires"`
}

type ResolveServerNameOpts struct {
	HTTPClient *http.Client
	DNSClient  *net.Resolver
}

var (
	ErrInvalidServerName = errors.New("invalid server name")
)

// ResolveServerName implements the full server discovery algorithm as specified in https://spec.matrix.org/v1.11/server-server-api/#resolving-server-names
func ResolveServerName(ctx context.Context, serverName string, opts ...*ResolveServerNameOpts) (*ResolvedServerName, error) {
	var opt ResolveServerNameOpts
	if len(opts) > 0 && opts[0] != nil {
		opt = *opts[0]
	}
	if opt.HTTPClient == nil {
		opt.HTTPClient = http.DefaultClient
	}
	if opt.DNSClient == nil {
		opt.DNSClient = net.DefaultResolver
	}
	output := ResolvedServerName{
		ServerName: serverName,
		HostHeader: serverName,
		IPPort:     []string{serverName},
		Expires:    time.Now().Add(24 * time.Hour),
	}
	hostname, port, ok := ParseServerName(serverName)
	if !ok {
		return nil, ErrInvalidServerName
	}
	// Steps 1 and 2: handle IP literals and hostnames with port
	if net.ParseIP(hostname) != nil || port != 0 {
		if port == 0 {
			port = 8448
		}
		output.IPPort = []string{net.JoinHostPort(hostname, strconv.Itoa(int(port)))}
		return &output, nil
	}
	// Step 3: resolve .well-known
	wellKnown, expiry, err := RequestWellKnown(ctx, opt.HTTPClient, hostname)
	if err != nil {
		zerolog.Ctx(ctx).Trace().
			Str("server_name", serverName).
			Err(err).
			Msg("Failed to get well-known data")
	} else if wellKnown != nil {
		output.Expires = expiry
		output.HostHeader = wellKnown.Server
		hostname, port, ok = ParseServerName(wellKnown.Server)
		// Step 3.1 and 3.2: IP literals and hostnames with port inside .well-known
		if net.ParseIP(hostname) != nil || port != 0 {
			if port == 0 {
				port = 8448
			}
			output.IPPort = []string{net.JoinHostPort(hostname, strconv.Itoa(int(port)))}
			return &output, nil
		}
	}
	// Step 3.3, 3.4, 4 and 5: resolve SRV records
	srv, err := RequestSRV(ctx, opt.DNSClient, hostname)
	if err != nil {
		// TODO log more noisily for abnormal errors?
		zerolog.Ctx(ctx).Trace().
			Str("server_name", serverName).
			Str("hostname", hostname).
			Err(err).
			Msg("Failed to get SRV record")
	} else if len(srv) > 0 {
		output.IPPort = make([]string, len(srv))
		for i, record := range srv {
			output.IPPort[i] = net.JoinHostPort(strings.TrimRight(record.Target, "."), strconv.Itoa(int(record.Port)))
		}
		return &output, nil
	}
	// Step 6 or 3.5: no SRV records were found, so default to port 8448
	output.IPPort = []string{net.JoinHostPort(hostname, "8448")}
	return &output, nil
}

// RequestSRV resolves the `_matrix-fed._tcp` SRV record for the given hostname.
// If the new matrix-fed record is not found, it falls back to the old `_matrix._tcp` record.
func RequestSRV(ctx context.Context, cli *net.Resolver, hostname string) ([]*net.SRV, error) {
	_, target, err := cli.LookupSRV(ctx, "matrix-fed", "tcp", hostname)
	var dnsErr *net.DNSError
	if err != nil && errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		_, target, err = cli.LookupSRV(ctx, "matrix", "tcp", hostname)
	}
	return target, err
}

func parseCacheControl(resp *http.Response) time.Duration {
	cc := resp.Header.Get("Cache-Control")
	if cc == "" {
		return 0
	}
	parts := strings.Split(cc, ",")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 1)
		switch kv[0] {
		case "no-cache", "no-store":
			return 0
		case "max-age":
			if len(kv) < 2 {
				continue
			}
			maxAge, err := strconv.Atoi(kv[1])
			if err != nil || maxAge < 0 {
				continue
			}
			age, _ := strconv.Atoi(resp.Header.Get("Age"))
			return time.Duration(maxAge-age) * time.Second
		}
	}
	return 0
}

const (
	MinCacheDuration     = 1 * time.Hour
	MaxCacheDuration     = 72 * time.Hour
	DefaultCacheDuration = 24 * time.Hour
)

// RequestWellKnown sends a request to the well-known endpoint of a server and returns the response,
// plus the time when the cache should expire.
func RequestWellKnown(ctx context.Context, cli *http.Client, hostname string) (*RespWellKnown, time.Time, error) {
	wellKnownURL := url.URL{
		Scheme: "https",
		Host:   hostname,
		Path:   "/.well-known/matrix/server",
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL.String(), nil)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to prepare request: %w", err)
	}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, time.Time{}, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
	var respData RespWellKnown
	err = json.NewDecoder(io.LimitReader(resp.Body, 50*1024)).Decode(&respData)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to decode response: %w", err)
	} else if respData.Server == "" {
		return nil, time.Time{}, errors.New("server name not found in response")
	}
	cacheDuration := parseCacheControl(resp)
	if cacheDuration <= 0 {
		cacheDuration = DefaultCacheDuration
	} else if cacheDuration < MinCacheDuration {
		cacheDuration = MinCacheDuration
	} else if cacheDuration > MaxCacheDuration {
		cacheDuration = MaxCacheDuration
	}
	return &respData, time.Now().Add(24 * time.Hour), nil
}
