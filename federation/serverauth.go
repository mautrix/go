// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"go.mau.fi/util/ptr"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
)

type ServerAuth struct {
	Keys           KeyCache
	Client         *Client
	GetDestination func(XMatrixAuth) string
	MaxBodySize    int64

	keyFetchLocks     map[string]*sync.Mutex
	keyFetchLocksLock sync.Mutex
}

func NewServerAuth(client *Client, keyCache KeyCache, getDestination func(auth XMatrixAuth) string) *ServerAuth {
	return &ServerAuth{
		Keys:           keyCache,
		Client:         client,
		GetDestination: getDestination,
		MaxBodySize:    50 * 1024 * 1024,
		keyFetchLocks:  make(map[string]*sync.Mutex),
	}
}

var MUnauthorized = mautrix.RespError{ErrCode: "M_UNAUTHORIZED", StatusCode: http.StatusUnauthorized}

var (
	errMissingAuthHeader       = MUnauthorized.WithMessage("Missing Authorization header")
	errInvalidAuthHeader       = MUnauthorized.WithMessage("Authorization header does not start with X-Matrix")
	errMalformedAuthHeader     = MUnauthorized.WithMessage("X-Matrix value is missing required components")
	errInvalidDestination      = MUnauthorized.WithMessage("Invalid destination in X-Matrix header")
	errFailedToQueryKeys       = MUnauthorized.WithMessage("Failed to query server keys")
	errInvalidSelfSignatures   = MUnauthorized.WithMessage("Server keys don't have valid self-signatures")
	errRequestBodyTooLarge     = mautrix.MTooLarge.WithMessage("Request body too large")
	errInvalidJSONBody         = mautrix.MBadJSON.WithMessage("Request body is not valid JSON")
	errBodyReadFailed          = mautrix.MUnknown.WithMessage("Failed to read request body")
	errInvalidRequestSignature = MUnauthorized.WithMessage("Failed to verify request signature")
)

type XMatrixAuth struct {
	Origin      string
	Destination string
	KeyID       id.KeyID
	Signature   string
}

func (xma XMatrixAuth) String() string {
	return fmt.Sprintf(
		`X-Matrix origin="%s",destination="%s",key="%s",sig="%s"`,
		xma.Origin,
		xma.Destination,
		xma.KeyID,
		xma.Signature,
	)
}

func ParseXMatrixAuth(auth string) (xma XMatrixAuth) {
	auth = strings.TrimPrefix(auth, "X-Matrix ")
	// TODO upgrade to strings.SplitSeq after Go 1.24 is the minimum
	for _, part := range strings.Split(auth, ",") {
		part = strings.TrimSpace(part)
		eqIdx := strings.Index(part, "=")
		if eqIdx == -1 || strings.Count(part, "=") > 1 {
			continue
		}
		val := strings.Trim(part[eqIdx+1:], "\"")
		switch strings.ToLower(part[:eqIdx]) {
		case "origin":
			xma.Origin = val
		case "destination":
			xma.Destination = val
		case "key":
			xma.KeyID = id.KeyID(val)
		case "sig":
			xma.Signature = val
		}
	}
	return
}

func (sa *ServerAuth) GetKeysWithCache(ctx context.Context, serverName string, keyID id.KeyID) (*ServerKeyResponse, error) {
	res, err := sa.Keys.LoadKeys(serverName)
	if err != nil {
		return nil, fmt.Errorf("failed to read cache: %w", err)
	} else if res.HasKey(keyID) {
		return res, nil
	}

	sa.keyFetchLocksLock.Lock()
	lock, ok := sa.keyFetchLocks[serverName]
	if !ok {
		lock = &sync.Mutex{}
		sa.keyFetchLocks[serverName] = lock
	}
	sa.keyFetchLocksLock.Unlock()

	lock.Lock()
	defer lock.Unlock()
	res, err = sa.Keys.LoadKeys(serverName)
	if err != nil {
		return nil, fmt.Errorf("failed to read cache: %w", err)
	} else if res != nil {
		if res.HasKey(keyID) {
			return res, nil
		} else if !sa.Keys.ShouldReQuery(serverName) {
			zerolog.Ctx(ctx).Trace().
				Str("server_name", serverName).
				Stringer("key_id", keyID).
				Msg("Not sending key request for missing key ID, last query was too recent")
			return res, nil
		}
	}
	res, err = sa.Client.ServerKeys(ctx, serverName)
	if err != nil {
		sa.Keys.StoreFetchError(serverName, err)
		return nil, err
	}
	sa.Keys.StoreKeys(res)
	return res, nil
}

type fixedLimitedReader struct {
	R   io.Reader
	N   int64
	Err error
}

func (l *fixedLimitedReader) Read(p []byte) (n int, err error) {
	if l.N <= 0 {
		return 0, l.Err
	}
	if int64(len(p)) > l.N {
		p = p[0:l.N]
	}
	n, err = l.R.Read(p)
	l.N -= int64(n)
	return
}

func (sa *ServerAuth) Authenticate(r *http.Request) (*http.Request, *mautrix.RespError) {
	defer func() {
		_ = r.Body.Close()
	}()
	log := zerolog.Ctx(r.Context())
	if r.ContentLength > sa.MaxBodySize {
		return nil, &errRequestBodyTooLarge
	}
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, &errMissingAuthHeader
	} else if !strings.HasPrefix(auth, "X-Matrix ") {
		return nil, &errInvalidAuthHeader
	}
	parsed := ParseXMatrixAuth(auth)
	if parsed.Origin == "" || parsed.KeyID == "" || parsed.Signature == "" {
		log.Trace().Str("auth_header", auth).Msg("Malformed X-Matrix header")
		return nil, &errMalformedAuthHeader
	}
	destination := sa.GetDestination(parsed)
	if destination == "" || (parsed.Destination != "" && parsed.Destination != destination) {
		log.Trace().
			Str("got_destination", parsed.Destination).
			Str("expected_destination", destination).
			Msg("Invalid destination in X-Matrix header")
		return nil, &errInvalidDestination
	}
	resp, err := sa.GetKeysWithCache(r.Context(), parsed.Origin, parsed.KeyID)
	if err != nil {
		if !errors.Is(err, ErrRecentKeyQueryFailed) {
			log.Err(err).
				Str("server_name", parsed.Origin).
				Msg("Failed to query keys to authenticate request")
		} else {
			log.Trace().Err(err).
				Str("server_name", parsed.Origin).
				Msg("Failed to query keys to authenticate request (cached error)")
		}
		return nil, &errFailedToQueryKeys
	} else if err := resp.VerifySelfSignature(); err != nil {
		log.Trace().Err(err).
			Str("server_name", parsed.Origin).
			Msg("Failed to validate self-signatures of server keys")
		return nil, &errInvalidSelfSignatures
	}
	key, ok := resp.VerifyKeys[parsed.KeyID]
	if !ok {
		keys := slices.Collect(maps.Keys(resp.VerifyKeys))
		log.Trace().
			Stringer("expected_key_id", parsed.KeyID).
			Any("found_key_ids", keys).
			Msg("Didn't find expected key ID to verify request")
		return nil, ptr.Ptr(MUnauthorized.WithMessage("Key ID %q not found (got %v)", parsed.KeyID, keys))
	}
	var reqBody []byte
	if r.ContentLength != 0 && r.Method != http.MethodGet && r.Method != http.MethodHead {
		reqBody, err = io.ReadAll(&fixedLimitedReader{R: r.Body, N: sa.MaxBodySize, Err: errRequestBodyTooLarge})
		if errors.Is(err, errRequestBodyTooLarge) {
			return nil, &errRequestBodyTooLarge
		} else if err != nil {
			log.Err(err).
				Str("server_name", parsed.Origin).
				Msg("Failed to read request body to authenticate")
			return nil, &errBodyReadFailed
		} else if !json.Valid(reqBody) {
			return nil, &errInvalidJSONBody
		}
	}
	err = (&signableRequest{
		Method:      r.Method,
		URI:         r.URL.EscapedPath(),
		Origin:      parsed.Origin,
		Destination: destination,
		Content:     reqBody,
	}).Verify(key.Key, parsed.Signature)
	if err != nil {
		log.Trace().Err(err).Msg("Request has invalid signature")
		return nil, &errInvalidRequestSignature
	}
	ctx := context.WithValue(r.Context(), contextKeyDestinationServer, destination)
	ctx = context.WithValue(ctx, contextKeyOriginServer, parsed.Origin)
	ctx = log.With().
		Str("origin_server_name", parsed.Origin).
		Str("destination_server_name", destination).
		Logger().WithContext(ctx)
	modifiedReq := r.WithContext(ctx)
	if reqBody != nil {
		modifiedReq.Body = io.NopCloser(bytes.NewReader(reqBody))
	}
	return modifiedReq, nil
}

func (sa *ServerAuth) AuthenticateMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if modifiedReq, err := sa.Authenticate(r); err != nil {
			err.Write(w)
		} else {
			next.ServeHTTP(w, modifiedReq)
		}
	})
}
