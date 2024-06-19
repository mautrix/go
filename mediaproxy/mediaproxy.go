// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mediaproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/federation"
)

type GetMediaResponse interface {
	isGetMediaResponse()
}

func (*GetMediaResponseURL) isGetMediaResponse()  {}
func (*GetMediaResponseData) isGetMediaResponse() {}

type GetMediaResponseURL struct {
	URL       string
	ExpiresAt time.Time
}

type GetMediaResponseData struct {
	Reader        io.ReadCloser
	ContentType   string
	ContentLength int64
}

type GetMediaFunc = func(ctx context.Context, mediaID string) (response GetMediaResponse, err error)

type MediaProxy struct {
	KeyServer   *federation.KeyServer
	ProxyClient *http.Client

	GetMedia            GetMediaFunc
	PrepareProxyRequest func(*http.Request)

	serverName string
	serverKey  *federation.SigningKey

	FederationRouter  *mux.Router
	LegacyMediaRouter *mux.Router
	ClientMediaRouter *mux.Router
}

func New(serverName string, serverKey string, getMedia GetMediaFunc) (*MediaProxy, error) {
	parsed, err := federation.ParseSynapseKey(serverKey)
	if err != nil {
		return nil, err
	}
	return &MediaProxy{
		serverName: serverName,
		serverKey:  parsed,
		GetMedia:   getMedia,
		ProxyClient: &http.Client{
			Transport: &http.Transport{
				DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
				TLSHandshakeTimeout: 10 * time.Second,
				ForceAttemptHTTP2:   false,
			},
			Timeout: 60 * time.Second,
		},
		KeyServer: &federation.KeyServer{
			KeyProvider: &federation.StaticServerKey{
				ServerName: serverName,
				Key:        parsed,
			},
			WellKnownTarget: fmt.Sprintf("%s:443", serverName),
			Version: federation.ServerVersion{
				Name:    "mautrix-go media proxy",
				Version: strings.TrimPrefix(mautrix.VersionWithCommit, "v"),
			},
		},
	}, nil
}

type BasicConfig struct {
	ServerName        string `yaml:"server_name" json:"server_name"`
	ServerKey         string `yaml:"server_key" json:"server_key"`
	AllowProxy        bool   `yaml:"allow_proxy" json:"allow_proxy"`
	WellKnownResponse string `yaml:"well_known_response" json:"well_known_response"`
}

func NewFromConfig(cfg BasicConfig, getMedia GetMediaFunc) (*MediaProxy, error) {
	mp, err := New(cfg.ServerName, cfg.ServerKey, getMedia)
	if err != nil {
		return nil, err
	}
	if !cfg.AllowProxy {
		mp.DisallowProxying()
	}
	if cfg.WellKnownResponse != "" {
		mp.KeyServer.WellKnownTarget = cfg.WellKnownResponse
	}
	return mp, nil
}

type ServerConfig struct {
	Hostname string `yaml:"hostname" json:"hostname"`
	Port     uint16 `yaml:"port" json:"port"`
}

func (mp *MediaProxy) Listen(cfg ServerConfig) error {
	router := mux.NewRouter()
	mp.RegisterRoutes(router)
	return http.ListenAndServe(fmt.Sprintf("%s:%d", cfg.Hostname, cfg.Port), router)
}

func (mp *MediaProxy) GetServerName() string {
	return mp.serverName
}

func (mp *MediaProxy) GetServerKey() *federation.SigningKey {
	return mp.serverKey
}

func (mp *MediaProxy) DisallowProxying() {
	mp.ProxyClient = nil
}

func (mp *MediaProxy) RegisterRoutes(router *mux.Router) {
	if mp.FederationRouter == nil {
		mp.FederationRouter = router.PathPrefix("/_matrix/federation").Subrouter()
	}
	if mp.LegacyMediaRouter == nil {
		mp.LegacyMediaRouter = router.PathPrefix("/_matrix/media").Subrouter()
	}
	if mp.ClientMediaRouter == nil {
		mp.ClientMediaRouter = router.PathPrefix("/_matrix/client/v1/media").Subrouter()
	}

	mp.FederationRouter.HandleFunc("/v1/media/download/{mediaID}", mp.DownloadMediaFederation).Methods(http.MethodGet)
	mp.FederationRouter.HandleFunc("/v1/version", mp.KeyServer.GetServerVersion).Methods(http.MethodGet)
	addClientRoutes := func(router *mux.Router, prefix string) {
		router.HandleFunc(prefix+"/download/{serverName}/{mediaID}", mp.DownloadMedia).Methods(http.MethodGet)
		router.HandleFunc(prefix+"/download/{serverName}/{mediaID}/{fileName}", mp.DownloadMedia).Methods(http.MethodGet)
		router.HandleFunc(prefix+"/thumbnail/{serverName}/{mediaID}", mp.DownloadMedia).Methods(http.MethodGet)
		router.HandleFunc(prefix+"/upload/{serverName}/{mediaID}", mp.UploadNotSupported).Methods(http.MethodPut)
		router.HandleFunc(prefix+"/upload", mp.UploadNotSupported).Methods(http.MethodPost)
		router.HandleFunc(prefix+"/create", mp.UploadNotSupported).Methods(http.MethodPost)
		router.HandleFunc(prefix+"/config", mp.UploadNotSupported).Methods(http.MethodGet)
		router.HandleFunc(prefix+"/preview_url", mp.PreviewURLNotSupported).Methods(http.MethodGet)
	}
	addClientRoutes(mp.LegacyMediaRouter, "/v3")
	addClientRoutes(mp.LegacyMediaRouter, "/r0")
	addClientRoutes(mp.LegacyMediaRouter, "/v1")
	addClientRoutes(mp.ClientMediaRouter, "")
	mp.LegacyMediaRouter.NotFoundHandler = http.HandlerFunc(mp.UnknownEndpoint)
	mp.LegacyMediaRouter.MethodNotAllowedHandler = http.HandlerFunc(mp.UnsupportedMethod)
	mp.FederationRouter.NotFoundHandler = http.HandlerFunc(mp.UnknownEndpoint)
	mp.FederationRouter.MethodNotAllowedHandler = http.HandlerFunc(mp.UnsupportedMethod)
	mp.ClientMediaRouter.NotFoundHandler = http.HandlerFunc(mp.UnknownEndpoint)
	mp.ClientMediaRouter.MethodNotAllowedHandler = http.HandlerFunc(mp.UnsupportedMethod)
	corsMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, Authorization")
			w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; script-src 'none'; plugin-types application/pdf; style-src 'unsafe-inline'; object-src 'self';")
			next.ServeHTTP(w, r)
		})
	}
	mp.LegacyMediaRouter.Use(corsMiddleware)
	mp.ClientMediaRouter.Use(corsMiddleware)
	mp.KeyServer.Register(router)
}

func (mp *MediaProxy) proxyDownload(ctx context.Context, w http.ResponseWriter, url, fileName string) {
	log := zerolog.Ctx(ctx)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Err(err).Str("url", url).Msg("Failed to create proxy request")
		jsonResponse(w, http.StatusInternalServerError, &mautrix.RespError{
			ErrCode: "M_UNKNOWN",
			Err:     "Failed to create proxy request",
		})
		return
	}
	if mp.PrepareProxyRequest != nil {
		mp.PrepareProxyRequest(req)
	}
	resp, err := mp.ProxyClient.Do(req)
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()
	if err != nil {
		log.Err(err).Str("url", url).Msg("Failed to proxy download")
		jsonResponse(w, http.StatusServiceUnavailable, &mautrix.RespError{
			ErrCode: "M_UNKNOWN",
			Err:     "Failed to proxy download",
		})
		return
	} else if resp.StatusCode != http.StatusOK {
		log.Warn().Str("url", url).Int("status", resp.StatusCode).Msg("Unexpected status code proxying download")
		jsonResponse(w, resp.StatusCode, &mautrix.RespError{
			ErrCode: "M_UNKNOWN",
			Err:     "Unexpected status code proxying download",
		})
		return
	}
	w.Header()["Content-Type"] = resp.Header["Content-Type"]
	w.Header()["Content-Length"] = resp.Header["Content-Length"]
	w.Header()["Last-Modified"] = resp.Header["Last-Modified"]
	w.Header()["Cache-Control"] = resp.Header["Cache-Control"]
	contentDisposition := "attachment"
	switch resp.Header.Get("Content-Type") {
	case "text/css", "text/plain", "text/csv", "application/json", "application/ld+json", "image/jpeg", "image/gif",
		"image/png", "image/apng", "image/webp", "image/avif", "video/mp4", "video/webm", "video/ogg", "video/quicktime",
		"audio/mp4", "audio/webm", "audio/aac", "audio/mpeg", "audio/ogg", "audio/wave", "audio/wav", "audio/x-wav",
		"audio/x-pn-wav", "audio/flac", "audio/x-flac", "application/pdf":
		contentDisposition = "inline"
	}
	if fileName != "" {
		contentDisposition = mime.FormatMediaType(contentDisposition, map[string]string{
			"filename": fileName,
		})
	}
	w.Header().Set("Content-Disposition", contentDisposition)
	w.WriteHeader(http.StatusOK)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to write proxy response")
	}
}

type ResponseError struct {
	Status int
	Data   any
}

func (err *ResponseError) Error() string {
	return fmt.Sprintf("HTTP %d: %v", err.Status, err.Data)
}

var ErrInvalidMediaIDSyntax = errors.New("invalid media ID syntax")

func (mp *MediaProxy) getMedia(w http.ResponseWriter, r *http.Request) GetMediaResponse {
	mediaID := mux.Vars(r)["mediaID"]
	resp, err := mp.GetMedia(r.Context(), mediaID)
	if err != nil {
		var respError *ResponseError
		if errors.Is(err, ErrInvalidMediaIDSyntax) {
			jsonResponse(w, http.StatusNotFound, &mautrix.RespError{
				ErrCode: mautrix.MNotFound.ErrCode,
				Err:     fmt.Sprintf("This is a media proxy at %q, other media downloads are not available here", mp.serverName),
			})
		} else if errors.As(err, &respError) {
			jsonResponse(w, respError.Status, respError.Data)
		} else {
			zerolog.Ctx(r.Context()).Err(err).Str("media_id", mediaID).Msg("Failed to get media URL")
			jsonResponse(w, http.StatusNotFound, &mautrix.RespError{
				ErrCode: mautrix.MNotFound.ErrCode,
				Err:     "Media not found",
			})
		}
		return nil
	}
	return resp
}

func (mp *MediaProxy) DownloadMediaFederation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := zerolog.Ctx(ctx)
	// TODO check destination header in X-Matrix auth

	resp := mp.getMedia(w, r)
	if resp == nil {
		return
	}

	mpw := multipart.NewWriter(w)
	w.Header().Set("Content-Type", strings.Replace(mpw.FormDataContentType(), "form-data", "mixed", 1))
	w.WriteHeader(http.StatusOK)
	metaPart, err := mpw.CreatePart(textproto.MIMEHeader{
		"Content-Type": {"application/json"},
	})
	if err != nil {
		log.Err(err).Msg("Failed to create multipart metadata field")
		return
	}
	_, err = metaPart.Write([]byte(`{}`))
	if err != nil {
		log.Err(err).Msg("Failed to write multipart metadata field")
		return
	}
	if urlResp, ok := resp.(*GetMediaResponseURL); ok {
		_, err = mpw.CreatePart(textproto.MIMEHeader{
			"Location": {urlResp.URL},
		})
		if err != nil {
			log.Err(err).Msg("Failed to create multipart redirect field")
			return
		}
	} else if dataResp, ok := resp.(*GetMediaResponseData); ok {
		dataPart, err := mpw.CreatePart(textproto.MIMEHeader{
			"Content-Type": {dataResp.ContentType},
		})
		if err != nil {
			log.Err(err).Msg("Failed to create multipart data field")
			return
		}
		_, err = io.Copy(dataPart, dataResp.Reader)
		if err != nil {
			log.Err(err).Msg("Failed to write multipart data field")
			return
		}
	} else {
		panic("unknown GetMediaResponse type")
	}
	err = mpw.Close()
	if err != nil {
		log.Err(err).Msg("Failed to close multipart writer")
		return
	}
}

func (mp *MediaProxy) DownloadMedia(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := zerolog.Ctx(ctx)
	vars := mux.Vars(r)
	if vars["serverName"] != mp.serverName {
		jsonResponse(w, http.StatusNotFound, &mautrix.RespError{
			ErrCode: mautrix.MNotFound.ErrCode,
			Err:     fmt.Sprintf("This is a media proxy at %q, other media downloads are not available here", mp.serverName),
		})
		return
	}
	resp := mp.getMedia(w, r)
	if resp == nil {
		return
	}

	if urlResp, ok := resp.(*GetMediaResponseURL); ok {
		// Proxy if the config allows proxying and the request doesn't allow redirects.
		// In any other case, redirect to the URL.
		if mp.ProxyClient != nil && r.URL.Query().Get("allow_redirect") != "true" {
			mp.proxyDownload(ctx, w, urlResp.URL, vars["fileName"])
			return
		}
		w.Header().Set("Location", urlResp.URL)
		expirySeconds := (time.Until(urlResp.ExpiresAt) - 5*time.Minute).Seconds()
		if urlResp.ExpiresAt.IsZero() {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else if expirySeconds > 0 {
			cacheControl := fmt.Sprintf("public, max-age=%d, immutable", int(expirySeconds))
			w.Header().Set("Cache-Control", cacheControl)
		} else {
			w.Header().Set("Cache-Control", "no-store")
		}
		w.WriteHeader(http.StatusTemporaryRedirect)
	} else if dataResp, ok := resp.(*GetMediaResponseData); ok {
		w.Header().Set("Content-Type", dataResp.ContentType)
		if dataResp.ContentLength != 0 {
			w.Header().Set("Content-Length", strconv.FormatInt(dataResp.ContentLength, 10))
		}
		w.WriteHeader(http.StatusOK)
		_, err := io.Copy(w, dataResp.Reader)
		if err != nil {
			log.Err(err).Msg("Failed to write media data")
		}
	} else {
		panic("unknown GetMediaResponse type")
	}
}

func jsonResponse(w http.ResponseWriter, status int, response interface{}) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(response)
}

func (mp *MediaProxy) UploadNotSupported(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusNotImplemented, &mautrix.RespError{
		ErrCode: mautrix.MUnrecognized.ErrCode,
		Err:     "This is a media proxy and does not support media uploads.",
	})
}

func (mp *MediaProxy) PreviewURLNotSupported(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusNotImplemented, &mautrix.RespError{
		ErrCode: mautrix.MUnrecognized.ErrCode,
		Err:     "This is a media proxy and does not support URL previews.",
	})
}

func (mp *MediaProxy) UnknownEndpoint(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusNotFound, &mautrix.RespError{
		ErrCode: mautrix.MUnrecognized.ErrCode,
		Err:     "Unrecognized endpoint",
	})
}

func (mp *MediaProxy) UnsupportedMethod(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusMethodNotAllowed, &mautrix.RespError{
		ErrCode: mautrix.MUnrecognized.ErrCode,
		Err:     "Invalid method for endpoint",
	})
}
