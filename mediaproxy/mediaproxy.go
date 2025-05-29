// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mediaproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
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

func (*GetMediaResponseURL) isGetMediaResponse()      {}
func (*GetMediaResponseData) isGetMediaResponse()     {}
func (*GetMediaResponseCallback) isGetMediaResponse() {}
func (*GetMediaResponseFile) isGetMediaResponse()     {}

type GetMediaResponseURL struct {
	URL       string
	ExpiresAt time.Time
}

type GetMediaResponseWriter interface {
	GetMediaResponse
	io.WriterTo
	GetContentType() string
	GetContentLength() int64
}

var (
	_ GetMediaResponseWriter = (*GetMediaResponseCallback)(nil)
	_ GetMediaResponseWriter = (*GetMediaResponseData)(nil)
)

type GetMediaResponseData struct {
	Reader        io.ReadCloser
	ContentType   string
	ContentLength int64
}

func (d *GetMediaResponseData) WriteTo(w io.Writer) (int64, error) {
	return io.Copy(w, d.Reader)
}

func (d *GetMediaResponseData) GetContentType() string {
	return d.ContentType
}

func (d *GetMediaResponseData) GetContentLength() int64 {
	return d.ContentLength
}

type GetMediaResponseCallback struct {
	Callback      func(w io.Writer) (int64, error)
	ContentType   string
	ContentLength int64
}

func (d *GetMediaResponseCallback) WriteTo(w io.Writer) (int64, error) {
	return d.Callback(w)
}

func (d *GetMediaResponseCallback) GetContentLength() int64 {
	return d.ContentLength
}

func (d *GetMediaResponseCallback) GetContentType() string {
	return d.ContentType
}

type GetMediaResponseFile struct {
	Callback    func(w *os.File) error
	ContentType string
}

type GetMediaFunc = func(ctx context.Context, mediaID string, params map[string]string) (response GetMediaResponse, err error)

type MediaProxy struct {
	KeyServer  *federation.KeyServer
	ServerAuth *federation.ServerAuth

	GetMedia            GetMediaFunc
	PrepareProxyRequest func(*http.Request)

	serverName string
	serverKey  *federation.SigningKey

	FederationRouter  *mux.Router
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
	FederationAuth    bool   `yaml:"federation_auth" json:"federation_auth"`
	WellKnownResponse string `yaml:"well_known_response" json:"well_known_response"`
}

func NewFromConfig(cfg BasicConfig, getMedia GetMediaFunc) (*MediaProxy, error) {
	mp, err := New(cfg.ServerName, cfg.ServerKey, getMedia)
	if err != nil {
		return nil, err
	}
	if cfg.WellKnownResponse != "" {
		mp.KeyServer.WellKnownTarget = cfg.WellKnownResponse
	}
	if cfg.FederationAuth {
		mp.EnableServerAuth(nil, nil)
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

func (mp *MediaProxy) EnableServerAuth(client *federation.Client, keyCache federation.KeyCache) {
	if keyCache == nil {
		keyCache = federation.NewInMemoryCache()
	}
	if client == nil {
		resCache, _ := keyCache.(federation.ResolutionCache)
		client = federation.NewClient(mp.serverName, mp.serverKey, resCache)
	}
	mp.ServerAuth = federation.NewServerAuth(client, keyCache, func(auth federation.XMatrixAuth) string {
		return mp.GetServerName()
	})
}

func (mp *MediaProxy) RegisterRoutes(router *mux.Router) {
	if mp.FederationRouter == nil {
		mp.FederationRouter = router.PathPrefix("/_matrix/federation").Subrouter()
	}
	if mp.ClientMediaRouter == nil {
		mp.ClientMediaRouter = router.PathPrefix("/_matrix/client/v1/media").Subrouter()
	}

	mp.FederationRouter.HandleFunc("/v1/media/download/{mediaID}", mp.DownloadMediaFederation).Methods(http.MethodGet)
	mp.FederationRouter.HandleFunc("/v1/version", mp.KeyServer.GetServerVersion).Methods(http.MethodGet)
	mp.ClientMediaRouter.HandleFunc("/download/{serverName}/{mediaID}", mp.DownloadMedia).Methods(http.MethodGet)
	mp.ClientMediaRouter.HandleFunc("/download/{serverName}/{mediaID}/{fileName}", mp.DownloadMedia).Methods(http.MethodGet)
	mp.ClientMediaRouter.HandleFunc("/thumbnail/{serverName}/{mediaID}", mp.DownloadMedia).Methods(http.MethodGet)
	mp.ClientMediaRouter.HandleFunc("/upload/{serverName}/{mediaID}", mp.UploadNotSupported).Methods(http.MethodPut)
	mp.ClientMediaRouter.HandleFunc("/upload", mp.UploadNotSupported).Methods(http.MethodPost)
	mp.ClientMediaRouter.HandleFunc("/create", mp.UploadNotSupported).Methods(http.MethodPost)
	mp.ClientMediaRouter.HandleFunc("/config", mp.UploadNotSupported).Methods(http.MethodGet)
	mp.ClientMediaRouter.HandleFunc("/preview_url", mp.PreviewURLNotSupported).Methods(http.MethodGet)
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
	mp.ClientMediaRouter.Use(corsMiddleware)
	mp.KeyServer.Register(router)
}

var ErrInvalidMediaIDSyntax = errors.New("invalid media ID syntax")

func queryToMap(vals url.Values) map[string]string {
	m := make(map[string]string, len(vals))
	for k, v := range vals {
		m[k] = v[0]
	}
	return m
}

func (mp *MediaProxy) getMedia(w http.ResponseWriter, r *http.Request) GetMediaResponse {
	mediaID := mux.Vars(r)["mediaID"]
	resp, err := mp.GetMedia(r.Context(), mediaID, queryToMap(r.URL.Query()))
	if err != nil {
		var mautrixRespError mautrix.RespError
		if errors.Is(err, ErrInvalidMediaIDSyntax) {
			mautrix.MNotFound.WithMessage("This is a media proxy at %q, other media downloads are not available here", mp.serverName).Write(w)
		} else if errors.As(err, &mautrixRespError) {
			mautrixRespError.Write(w)
		} else {
			zerolog.Ctx(r.Context()).Err(err).Str("media_id", mediaID).Msg("Failed to get media URL")
			mautrix.MNotFound.WithMessage("Media not found").Write(w)
		}
		return nil
	}
	return resp
}

func startMultipart(ctx context.Context, w http.ResponseWriter) *multipart.Writer {
	mpw := multipart.NewWriter(w)
	w.Header().Set("Content-Type", strings.Replace(mpw.FormDataContentType(), "form-data", "mixed", 1))
	w.WriteHeader(http.StatusOK)
	metaPart, err := mpw.CreatePart(textproto.MIMEHeader{
		"Content-Type": {"application/json"},
	})
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to create multipart metadata field")
		return nil
	}
	_, err = metaPart.Write([]byte(`{}`))
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to write multipart metadata field")
		return nil
	}
	return mpw
}

func (mp *MediaProxy) DownloadMediaFederation(w http.ResponseWriter, r *http.Request) {
	if mp.ServerAuth != nil {
		var err *mautrix.RespError
		r, err = mp.ServerAuth.Authenticate(r)
		if err != nil {
			err.Write(w)
			return
		}
	}
	ctx := r.Context()
	log := zerolog.Ctx(ctx)

	resp := mp.getMedia(w, r)
	if resp == nil {
		return
	}

	var mpw *multipart.Writer
	if urlResp, ok := resp.(*GetMediaResponseURL); ok {
		mpw = startMultipart(ctx, w)
		if mpw == nil {
			return
		}
		_, err := mpw.CreatePart(textproto.MIMEHeader{
			"Location": {urlResp.URL},
		})
		if err != nil {
			log.Err(err).Msg("Failed to create multipart redirect field")
			return
		}
	} else if fileResp, ok := resp.(*GetMediaResponseFile); ok {
		responseStarted, err := doTempFileDownload(fileResp, func(wt io.WriterTo, size int64, mimeType string) error {
			mpw = startMultipart(ctx, w)
			if mpw == nil {
				return fmt.Errorf("failed to start multipart writer")
			}
			dataPart, err := mpw.CreatePart(textproto.MIMEHeader{
				"Content-Type": {mimeType},
			})
			if err != nil {
				return fmt.Errorf("failed to create multipart data field: %w", err)
			}
			_, err = wt.WriteTo(dataPart)
			return err
		})
		if err != nil {
			log.Err(err).Msg("Failed to do media proxy with temp file")
			if !responseStarted {
				var mautrixRespError mautrix.RespError
				if errors.As(err, &mautrixRespError) {
					mautrixRespError.Write(w)
				} else {
					mautrix.MUnknown.WithMessage("Internal error proxying media").Write(w)
				}
			}
			return
		}
	} else if dataResp, ok := resp.(GetMediaResponseWriter); ok {
		mpw = startMultipart(ctx, w)
		if mpw == nil {
			return
		}
		dataPart, err := mpw.CreatePart(textproto.MIMEHeader{
			"Content-Type": {dataResp.GetContentType()},
		})
		if err != nil {
			log.Err(err).Msg("Failed to create multipart data field")
			return
		}
		_, err = dataResp.WriteTo(dataPart)
		if err != nil {
			log.Err(err).Msg("Failed to write multipart data field")
			return
		}
	} else {
		panic(fmt.Errorf("unknown GetMediaResponse type %T", resp))
	}
	err := mpw.Close()
	if err != nil {
		log.Err(err).Msg("Failed to close multipart writer")
		return
	}
}

func (mp *MediaProxy) addHeaders(w http.ResponseWriter, mimeType, fileName string) {
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	contentDisposition := "attachment"
	switch mimeType {
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
	w.Header().Set("Content-Type", mimeType)
}

func (mp *MediaProxy) DownloadMedia(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := zerolog.Ctx(ctx)
	vars := mux.Vars(r)
	if vars["serverName"] != mp.serverName {
		mautrix.MNotFound.WithMessage("This is a media proxy at %q, other media downloads are not available here", mp.serverName).Write(w)
		return
	}
	resp := mp.getMedia(w, r)
	if resp == nil {
		return
	}

	if urlResp, ok := resp.(*GetMediaResponseURL); ok {
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
	} else if fileResp, ok := resp.(*GetMediaResponseFile); ok {
		responseStarted, err := doTempFileDownload(fileResp, func(wt io.WriterTo, size int64, mimeType string) error {
			mp.addHeaders(w, mimeType, vars["fileName"])
			w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
			w.WriteHeader(http.StatusOK)
			_, err := wt.WriteTo(w)
			return err
		})
		if err != nil {
			log.Err(err).Msg("Failed to do media proxy with temp file")
			if !responseStarted {
				var mautrixRespError mautrix.RespError
				if errors.As(err, &mautrixRespError) {
					mautrixRespError.Write(w)
				} else {
					mautrix.MUnknown.WithMessage("Internal error proxying media").Write(w)
				}
			}
		}
	} else if dataResp, ok := resp.(GetMediaResponseWriter); ok {
		mp.addHeaders(w, dataResp.GetContentType(), vars["fileName"])
		if dataResp.GetContentLength() != 0 {
			w.Header().Set("Content-Length", strconv.FormatInt(dataResp.GetContentLength(), 10))
		}
		w.WriteHeader(http.StatusOK)
		_, err := dataResp.WriteTo(w)
		if err != nil {
			log.Err(err).Msg("Failed to write media data")
		}
	} else {
		panic(fmt.Errorf("unknown GetMediaResponse type %T", resp))
	}
}

func doTempFileDownload(
	data *GetMediaResponseFile,
	respond func(w io.WriterTo, size int64, mimeType string) error,
) (bool, error) {
	tempFile, err := os.CreateTemp("", "mautrix-mediaproxy-*")
	if err != nil {
		return false, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() {
		_ = tempFile.Close()
		_ = os.Remove(tempFile.Name())
	}()
	err = data.Callback(tempFile)
	if err != nil {
		return false, err
	}
	_, err = tempFile.Seek(0, io.SeekStart)
	if err != nil {
		return false, fmt.Errorf("failed to seek to start of temp file: %w", err)
	}
	fileInfo, err := tempFile.Stat()
	if err != nil {
		return false, fmt.Errorf("failed to stat temp file: %w", err)
	}
	mimeType := data.ContentType
	if mimeType == "" {
		buf := make([]byte, 512)
		n, err := tempFile.Read(buf)
		if err != nil {
			return false, fmt.Errorf("failed to read temp file to detect mime: %w", err)
		}
		buf = buf[:n]
		_, err = tempFile.Seek(0, io.SeekStart)
		if err != nil {
			return false, fmt.Errorf("failed to seek to start of temp file: %w", err)
		}
		mimeType = http.DetectContentType(buf)
	}
	err = respond(tempFile, fileInfo.Size(), mimeType)
	if err != nil {
		return true, err
	}
	return true, nil
}

var (
	ErrUploadNotSupported = mautrix.MUnrecognized.
				WithMessage("This is a media proxy and does not support media uploads.").
				WithStatus(http.StatusNotImplemented)
	ErrPreviewURLNotSupported = mautrix.MUnrecognized.
					WithMessage("This is a media proxy and does not support URL previews.").
					WithStatus(http.StatusNotImplemented)
	ErrUnknownEndpoint = mautrix.MUnrecognized.
				WithMessage("Unrecognized endpoint")
	ErrUnsupportedMethod = mautrix.MUnrecognized.
				WithMessage("Invalid method for endpoint").
				WithStatus(http.StatusMethodNotAllowed)
)

func (mp *MediaProxy) UploadNotSupported(w http.ResponseWriter, r *http.Request) {
	ErrUploadNotSupported.Write(w)
}

func (mp *MediaProxy) PreviewURLNotSupported(w http.ResponseWriter, r *http.Request) {
	ErrPreviewURLNotSupported.Write(w)
}

func (mp *MediaProxy) UnknownEndpoint(w http.ResponseWriter, r *http.Request) {
	ErrUnknownEndpoint.Write(w)
}

func (mp *MediaProxy) UnsupportedMethod(w http.ResponseWriter, r *http.Request) {
	ErrUnsupportedMethod.Write(w)
}
