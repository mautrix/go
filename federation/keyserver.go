// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package federation

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"go.mau.fi/util/exerrors"
	"go.mau.fi/util/exhttp"
	"go.mau.fi/util/jsontime"
	"go.mau.fi/util/ptr"
	"go.mau.fi/util/requestlog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
)

type ServerVersion struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ServerKeyProvider is an interface that returns private server keys for server key requests.
type ServerKeyProvider interface {
	Get(r *http.Request) (serverName string, key *SigningKey)
}

// StaticServerKey is an implementation of [ServerKeyProvider] that always returns the same server name and key.
type StaticServerKey struct {
	ServerName string
	Key        *SigningKey
}

func (ssk *StaticServerKey) Get(r *http.Request) (serverName string, key *SigningKey) {
	return ssk.ServerName, ssk.Key
}

// KeyServer implements a basic Matrix key server that can serve its own keys, plus the federation version endpoint.
//
// It does not implement querying keys of other servers, nor any other federation endpoints.
type KeyServer struct {
	KeyProvider     ServerKeyProvider
	Version         ServerVersion
	WellKnownTarget string
	OtherKeys       KeyCache
}

// Register registers the key server endpoints to the given router.
func (ks *KeyServer) Register(r *http.ServeMux, log zerolog.Logger) {
	r.HandleFunc("GET /.well-known/matrix/server", ks.GetWellKnown)
	r.HandleFunc("GET /_matrix/federation/v1/version", ks.GetServerVersion)
	keyRouter := http.NewServeMux()
	keyRouter.HandleFunc("GET /v2/server", ks.GetServerKey)
	keyRouter.HandleFunc("GET /v2/query/{serverName}", ks.GetQueryKeys)
	keyRouter.HandleFunc("POST /v2/query", ks.PostQueryKeys)
	errorBodies := exhttp.ErrorBodies{
		NotFound:         exerrors.Must(ptr.Ptr(mautrix.MUnrecognized.WithMessage("Unrecognized endpoint")).MarshalJSON()),
		MethodNotAllowed: exerrors.Must(ptr.Ptr(mautrix.MUnrecognized.WithMessage("Invalid method for endpoint")).MarshalJSON()),
	}
	r.Handle("/_matrix/key/", exhttp.ApplyMiddleware(
		keyRouter,
		exhttp.StripPrefix("/_matrix/key"),
		hlog.NewHandler(log),
		hlog.RequestIDHandler("request_id", "Request-Id"),
		requestlog.AccessLogger(requestlog.Options{TrustXForwardedFor: true}),
		exhttp.HandleErrors(errorBodies),
	))
}

// RespWellKnown is the response body for the `GET /.well-known/matrix/server` endpoint.
type RespWellKnown struct {
	Server string `json:"m.server"`
}

// GetWellKnown implements the `GET /.well-known/matrix/server` endpoint
//
// https://spec.matrix.org/v1.9/server-server-api/#get_well-knownmatrixserver
func (ks *KeyServer) GetWellKnown(w http.ResponseWriter, r *http.Request) {
	if ks.WellKnownTarget == "" {
		mautrix.MNotFound.WithMessage("No well-known target set").Write(w)
	} else {
		exhttp.WriteJSONResponse(w, http.StatusOK, &RespWellKnown{Server: ks.WellKnownTarget})
	}
}

// RespServerVersion is the response body for the `GET /_matrix/federation/v1/version` endpoint
type RespServerVersion struct {
	Server ServerVersion `json:"server"`
}

// GetServerVersion implements the `GET /_matrix/federation/v1/version` endpoint
//
// https://spec.matrix.org/v1.9/server-server-api/#get_matrixfederationv1version
func (ks *KeyServer) GetServerVersion(w http.ResponseWriter, r *http.Request) {
	exhttp.WriteJSONResponse(w, http.StatusOK, &RespServerVersion{Server: ks.Version})
}

// GetServerKey implements the `GET /_matrix/key/v2/server` endpoint.
//
// https://spec.matrix.org/v1.9/server-server-api/#get_matrixkeyv2server
func (ks *KeyServer) GetServerKey(w http.ResponseWriter, r *http.Request) {
	domain, key := ks.KeyProvider.Get(r)
	if key == nil {
		mautrix.MNotFound.WithMessage("No signing key found for %q", r.Host).Write(w)
	} else {
		exhttp.WriteJSONResponse(w, http.StatusOK, key.GenerateKeyResponse(domain, nil))
	}
}

// ReqQueryKeys is the request body for the `POST /_matrix/key/v2/query` endpoint
type ReqQueryKeys struct {
	ServerKeys map[string]map[id.KeyID]QueryKeysCriteria `json:"server_keys"`
}

type QueryKeysCriteria struct {
	MinimumValidUntilTS jsontime.UnixMilli `json:"minimum_valid_until_ts"`
}

// PostQueryKeysResponse is the response body for the `POST /_matrix/key/v2/query` endpoint
type PostQueryKeysResponse struct {
	ServerKeys map[string]*ServerKeyResponse `json:"server_keys"`
}

// PostQueryKeys implements the `POST /_matrix/key/v2/query` endpoint
//
// https://spec.matrix.org/v1.9/server-server-api/#post_matrixkeyv2query
func (ks *KeyServer) PostQueryKeys(w http.ResponseWriter, r *http.Request) {
	var req ReqQueryKeys
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		mautrix.MBadJSON.WithMessage("failed to parse request: %v", err).Write(w)
		return
	}

	resp := &PostQueryKeysResponse{
		ServerKeys: make(map[string]*ServerKeyResponse),
	}
	for serverName, keys := range req.ServerKeys {
		domain, key := ks.KeyProvider.Get(r)
		if domain != serverName {
			continue
		}
		for keyID, criteria := range keys {
			if key.ID == keyID && criteria.MinimumValidUntilTS.Before(time.Now().Add(24*time.Hour)) {
				resp.ServerKeys[serverName] = key.GenerateKeyResponse(serverName, nil)
			}
		}
	}
	exhttp.WriteJSONResponse(w, http.StatusOK, resp)
}

// GetQueryKeysResponse is the response body for the `GET /_matrix/key/v2/query/{serverName}` endpoint
type GetQueryKeysResponse struct {
	ServerKeys []*ServerKeyResponse `json:"server_keys"`
}

// GetQueryKeys implements the `GET /_matrix/key/v2/query/{serverName}` endpoint
//
// https://spec.matrix.org/v1.9/server-server-api/#get_matrixkeyv2queryservername
func (ks *KeyServer) GetQueryKeys(w http.ResponseWriter, r *http.Request) {
	serverName := r.PathValue("serverName")
	minimumValidUntilTSString := r.URL.Query().Get("minimum_valid_until_ts")
	minimumValidUntilTS, err := strconv.ParseInt(minimumValidUntilTSString, 10, 64)
	if err != nil && minimumValidUntilTSString != "" {
		mautrix.MInvalidParam.WithMessage("failed to parse ?minimum_valid_until_ts: %v", err).Write(w)
		return
	} else if time.UnixMilli(minimumValidUntilTS).After(time.Now().Add(24 * time.Hour)) {
		mautrix.MInvalidParam.WithMessage("minimum_valid_until_ts may not be more than 24 hours in the future").Write(w)
		return
	}
	resp := &GetQueryKeysResponse{
		ServerKeys: []*ServerKeyResponse{},
	}
	domain, key := ks.KeyProvider.Get(r)
	if domain == serverName {
		if key != nil {
			resp.ServerKeys = append(resp.ServerKeys, key.GenerateKeyResponse(serverName, nil))
		}
	} else if ks.OtherKeys != nil {
		otherKey, err := ks.OtherKeys.LoadKeys(serverName)
		if err != nil {
			mautrix.MUnknown.WithMessage("Failed to load keys from cache").Write(w)
			return
		}
		if key != nil && domain != "" {
			signature, err := key.SignJSON(otherKey)
			if err == nil {
				otherKey.Signatures[domain] = map[id.KeyID]string{
					key.ID: signature,
				}
			}
		}
		resp.ServerKeys = append(resp.ServerKeys, otherKey)
	}
	exhttp.WriteJSONResponse(w, http.StatusOK, resp)
}
