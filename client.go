// Package mautrix implements the Matrix Client-Server API.
//
// Specification can be found at http://matrix.org/docs/spec/client_server/r0.4.0.html
package mautrix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/pushrules"
)

type Logger interface {
	Debugfln(message string, args ...interface{})
}

// StubLogger is an implementation of Logger that does nothing
type StubLogger struct{}

func (sl *StubLogger) Debugfln(message string, args ...interface{}) {}
func (sl *StubLogger) Warnfln(message string, args ...interface{})  {}

var stubLogger = &StubLogger{}

type WarnLogger interface {
	Logger
	Warnfln(message string, args ...interface{})
}

type Stringifiable interface {
	String() string
}

// Client represents a Matrix client.
type Client struct {
	HomeserverURL *url.URL     // The base homeserver URL
	Prefix        URLPath      // The API prefix eg '/_matrix/client/r0'
	UserID        id.UserID    // The user ID of the client. Used for forming HTTP paths which use the client's user ID.
	DeviceID      id.DeviceID  // The device ID of the client.
	AccessToken   string       // The access_token for the client.
	UserAgent     string       // The value for the User-Agent header
	Client        *http.Client // The underlying HTTP client which will be used to make HTTP requests.
	Syncer        Syncer       // The thing which can process /sync responses
	Store         Storer       // The thing which can store rooms/tokens/ids
	Logger        Logger
	SyncPresence  event.Presence

	StreamSyncMinAge time.Duration

	// Number of times that mautrix will retry any HTTP request
	// if the request fails entirely or returns a HTTP gateway error (502-504)
	DefaultHTTPRetries int

	txnID int32

	// The ?user_id= query parameter for application services. This must be set *prior* to calling a method. If this is empty,
	// no user_id parameter will be sent.
	// See http://matrix.org/docs/spec/application_service/unstable.html#identity-assertion
	AppServiceUserID id.UserID

	syncingID uint32 // Identifies the current Sync. Only one Sync can be active at any given time.
}

type ClientWellKnown struct {
	Homeserver     HomeserverInfo     `json:"m.homeserver"`
	IdentityServer IdentityServerInfo `json:"m.identity_server"`
}

type HomeserverInfo struct {
	BaseURL string `json:"base_url"`
}

type IdentityServerInfo struct {
	BaseURL string `json:"base_url"`
}

// DiscoverClientAPI resolves the client API URL from a Matrix server name.
// Use ParseUserID to extract the server name from a user ID.
// https://matrix.org/docs/spec/client_server/r0.6.0#server-discovery
func DiscoverClientAPI(serverName string) (*ClientWellKnown, error) {
	wellKnownURL := url.URL{
		Scheme: "https",
		Host:   serverName,
		Path:   "/.well-known/matrix/client",
	}

	req, err := http.NewRequest("GET", wellKnownURL.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", DefaultUserAgent+" .well-known fetcher")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var wellKnown ClientWellKnown
	err = json.Unmarshal(data, &wellKnown)
	if err != nil {
		return nil, errors.New(".well-known response not JSON")
	}

	return &wellKnown, nil
}

// BuildURL builds a URL with the given path parts
func BuildURL(baseURL *url.URL, path ...interface{}) *url.URL {
	createdURL := *baseURL
	rawParts := make([]string, len(path)+1)
	rawParts[0] = strings.TrimSuffix(createdURL.EscapedPath(), "/")
	parts := make([]string, len(path)+1)
	parts[0] = strings.TrimSuffix(createdURL.Path, "/")
	for i, part := range path {
		switch casted := part.(type) {
		case string:
			parts[i+1] = casted
		case int:
			parts[i+1] = strconv.Itoa(casted)
		case Stringifiable:
			parts[i+1] = casted.String()
		default:
			parts[i+1] = fmt.Sprint(casted)
		}
		rawParts[i+1] = url.PathEscape(parts[i+1])
	}
	createdURL.Path = strings.Join(parts, "/")
	createdURL.RawPath = strings.Join(rawParts, "/")
	return &createdURL
}

// BuildURL builds a URL with the Client's homeserver and appservice user ID set already.
func (cli *Client) BuildURL(urlPath ...interface{}) string {
	return cli.BuildBaseURL(append(cli.Prefix, urlPath...)...)
}

// BuildBaseURL builds a URL with the Client's homeserver and appservice user ID set already.
// You must supply the prefix in the path.
func (cli *Client) BuildBaseURL(urlPath ...interface{}) string {
	return cli.BuildBaseURLWithQuery(urlPath, nil)
}

type URLPath = []interface{}

// BuildURLWithQuery builds a URL with query parameters in addition to the Client's
// homeserver and appservice user ID set already.
func (cli *Client) BuildURLWithQuery(urlPath URLPath, urlQuery map[string]string) string {
	return cli.BuildBaseURLWithQuery(append(cli.Prefix, urlPath...), urlQuery)
}

// BuildBaseURLWithQuery builds a URL with query parameters in addition to the Client's homeserver
// and appservice user ID set already. You must supply the prefix in the path.
func (cli *Client) BuildBaseURLWithQuery(urlPath URLPath, urlQuery map[string]string) string {
	// Dereference the URL to copy it
	hsURL := *cli.HomeserverURL
	if hsURL.Scheme == "" {
		hsURL.Scheme = "https"
	}
	hsURL = *BuildURL(&hsURL, urlPath...)
	query := hsURL.Query()
	if cli.AppServiceUserID != "" {
		query.Set("user_id", string(cli.AppServiceUserID))
	}
	if urlQuery != nil {
		for k, v := range urlQuery {
			query.Set(k, v)
		}
	}
	hsURL.RawQuery = query.Encode()
	return hsURL.String()
}

// SetCredentials sets the user ID and access token on this client instance.
//
// Deprecated: use the StoreCredentials field in ReqLogin instead.
func (cli *Client) SetCredentials(userID id.UserID, accessToken string) {
	cli.AccessToken = accessToken
	cli.UserID = userID
}

// ClearCredentials removes the user ID and access token on this client instance.
func (cli *Client) ClearCredentials() {
	cli.AccessToken = ""
	cli.UserID = ""
	cli.DeviceID = ""
}

// Sync starts syncing with the provided Homeserver. If Sync() is called twice then the first sync will be stopped and the
// error will be nil.
//
// This function will block until a fatal /sync error occurs, so it should almost always be started as a new goroutine.
// Fatal sync errors can be caused by:
//   - The failure to create a filter.
//   - Client.Syncer.OnFailedSync returning an error in response to a failed sync.
//   - Client.Syncer.ProcessResponse returning an error.
// If you wish to continue retrying in spite of these fatal errors, call Sync() again.
func (cli *Client) Sync() error {
	return cli.SyncWithContext(context.Background())
}

func (cli *Client) SyncWithContext(ctx context.Context) error {
	// Mark the client as syncing.
	// We will keep syncing until the syncing state changes. Either because
	// Sync is called or StopSync is called.
	syncingID := cli.incrementSyncingID()
	nextBatch := cli.Store.LoadNextBatch(cli.UserID)
	filterID := cli.Store.LoadFilterID(cli.UserID)
	if filterID == "" {
		filterJSON := cli.Syncer.GetFilterJSON(cli.UserID)
		resFilter, err := cli.CreateFilter(filterJSON)
		if err != nil {
			return err
		}
		filterID = resFilter.FilterID
		cli.Store.SaveFilterID(cli.UserID, filterID)
	}
	lastSuccessfulSync := time.Now().Add(-cli.StreamSyncMinAge - 1*time.Hour)
	for {
		streamResp := false
		if cli.StreamSyncMinAge > 0 && time.Since(lastSuccessfulSync) > cli.StreamSyncMinAge {
			cli.Logger.Debugfln("Last sync is old, will stream next response")
			streamResp = true
		}
		resSync, err := cli.FullSyncRequest(ReqSync{
			Timeout:        30000,
			Since:          nextBatch,
			FilterID:       filterID,
			FullState:      false,
			SetPresence:    cli.SyncPresence,
			Context:        ctx,
			StreamResponse: streamResp,
		})
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			duration, err2 := cli.Syncer.OnFailedSync(resSync, err)
			if err2 != nil {
				return err2
			}
			time.Sleep(duration)
			continue
		}
		lastSuccessfulSync = time.Now()

		// Check that the syncing state hasn't changed
		// Either because we've stopped syncing or another sync has been started.
		// We discard the response from our sync.
		if cli.getSyncingID() != syncingID {
			return nil
		}

		// Save the token now *before* processing it. This means it's possible
		// to not process some events, but it means that we won't get constantly stuck processing
		// a malformed/buggy event which keeps making us panic.
		cli.Store.SaveNextBatch(cli.UserID, resSync.NextBatch)
		if err = cli.Syncer.ProcessResponse(resSync, nextBatch); err != nil {
			return err
		}

		nextBatch = resSync.NextBatch
	}
}

func (cli *Client) incrementSyncingID() uint32 {
	return atomic.AddUint32(&cli.syncingID, 1)
}

func (cli *Client) getSyncingID() uint32 {
	return atomic.LoadUint32(&cli.syncingID)
}

// StopSync stops the ongoing sync started by Sync.
func (cli *Client) StopSync() {
	// Advance the syncing state so that any running Syncs will terminate.
	cli.incrementSyncingID()
}

const logBodyContextKey = "fi.mau.mautrix.log_body"
const logRequestIDContextKey = "fi.mau.mautrix.request_id"

func (cli *Client) LogRequest(req *http.Request) {
	if cli.Logger == stubLogger {
		return
	}
	body, ok := req.Context().Value(logBodyContextKey).(string)
	reqID, _ := req.Context().Value(logRequestIDContextKey).(int)
	if ok && len(body) > 0 {
		cli.Logger.Debugfln("req #%d: %s %s %s", reqID, req.Method, req.URL.String(), body)
	} else {
		cli.Logger.Debugfln("req #%d: %s %s", reqID, req.Method, req.URL.String())
	}
}

func (cli *Client) MakeRequest(method string, httpURL string, reqBody interface{}, resBody interface{}) ([]byte, error) {
	return cli.MakeFullRequest(FullRequest{Method: method, URL: httpURL, RequestJSON: reqBody, ResponseJSON: resBody})
}

type ClientResponseHandler = func(req *http.Request, res *http.Response, responseJSON interface{}) ([]byte, error)

type FullRequest struct {
	Method           string
	URL              string
	Headers          http.Header
	RequestJSON      interface{}
	RequestBytes     []byte
	RequestBody      io.Reader
	RequestLength    int64
	ResponseJSON     interface{}
	Context          context.Context
	MaxAttempts      int
	SensitiveContent bool
	Handler          ClientResponseHandler
}

var requestID int32
var logSensitiveContent = os.Getenv("MAUTRIX_LOG_SENSITIVE_CONTENT") == "yes"

func (params *FullRequest) compileRequest() (*http.Request, error) {
	var logBody string
	reqBody := params.RequestBody
	if params.Context == nil {
		params.Context = context.Background()
	}
	if params.RequestJSON != nil {
		jsonStr, err := json.Marshal(params.RequestJSON)
		if err != nil {
			return nil, HTTPError{
				Message:      "failed to marshal JSON",
				WrappedError: err,
			}
		}
		if params.SensitiveContent && !logSensitiveContent {
			logBody = "<sensitive content omitted>"
		} else {
			logBody = string(jsonStr)
		}
		reqBody = bytes.NewReader(jsonStr)
	} else if params.RequestBytes != nil {
		logBody = fmt.Sprintf("<%d bytes>", len(params.RequestBytes))
		reqBody = bytes.NewReader(params.RequestBytes)
		params.RequestLength = int64(len(params.RequestBytes))
	} else if params.RequestLength > 0 && params.RequestBody != nil {
		logBody = fmt.Sprintf("<%d bytes>", params.RequestLength)
	}
	ctx := context.WithValue(params.Context, logBodyContextKey, logBody)
	reqID := atomic.AddInt32(&requestID, 1)
	ctx = context.WithValue(ctx, logRequestIDContextKey, int(reqID))
	req, err := http.NewRequestWithContext(ctx, params.Method, params.URL, reqBody)
	if err != nil {
		return nil, HTTPError{
			Message:      "failed to create request",
			WrappedError: err,
		}
	}
	if params.Headers != nil {
		req.Header = params.Headers
	}
	if params.RequestJSON != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if params.RequestLength > 0 && params.RequestBody != nil {
		req.ContentLength = params.RequestLength
	}
	return req, nil
}

// MakeFullRequest makes a JSON HTTP request to the given URL.
// If "resBody" is not nil, the response body will be json.Unmarshalled into it.
//
// Returns the HTTP body as bytes on 2xx with a nil error. Returns an error if the response is not 2xx along
// with the HTTP body bytes if it got that far. This error is an HTTPError which includes the returned
// HTTP status code and possibly a RespError as the WrappedError, if the HTTP body could be decoded as a RespError.
func (cli *Client) MakeFullRequest(params FullRequest) ([]byte, error) {
	if params.MaxAttempts == 0 {
		params.MaxAttempts = 1 + cli.DefaultHTTPRetries
	}
	req, err := params.compileRequest()
	if err != nil {
		return nil, err
	}
	if params.Handler == nil {
		params.Handler = cli.handleNormalResponse
	}
	req.Header.Set("User-Agent", cli.UserAgent)
	if len(cli.AccessToken) > 0 {
		req.Header.Set("Authorization", "Bearer "+cli.AccessToken)
	}
	return cli.executeCompiledRequest(req, params.MaxAttempts-1, 4*time.Second, params.ResponseJSON, params.Handler)
}

func (cli *Client) logWarning(format string, args ...interface{}) {
	warnLogger, ok := cli.Logger.(WarnLogger)
	if ok {
		warnLogger.Warnfln(format, args...)
	} else {
		cli.Logger.Debugfln(format, args...)
	}
}

func (cli *Client) doRetry(req *http.Request, cause error, retries int, backoff time.Duration, responseJSON interface{}, handler ClientResponseHandler) ([]byte, error) {
	reqID, _ := req.Context().Value(logRequestIDContextKey).(int)
	if req.Body != nil {
		if req.GetBody == nil {
			cli.logWarning("Failed to get new body to retry request #%d: GetBody is nil", reqID)
			return nil, cause
		}
		var err error
		req.Body, err = req.GetBody()
		if err != nil {
			cli.logWarning("Failed to get new body to retry request #%d: %v", reqID, err)
			return nil, cause
		}
	}
	cli.logWarning("Request #%d failed: %v, retrying in %d seconds", reqID, cause, int(backoff.Seconds()))
	time.Sleep(backoff)
	return cli.executeCompiledRequest(req, retries-1, backoff*2, responseJSON, handler)
}

func (cli *Client) readRequestBody(req *http.Request, res *http.Response) ([]byte, error) {
	contents, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, HTTPError{
			Request:  req,
			Response: res,

			Message:      "failed to read response body",
			WrappedError: err,
		}
	}
	return contents, nil
}

func (cli *Client) closeTemp(file *os.File) {
	_ = file.Close()
	err := os.Remove(file.Name())
	if err != nil {
		cli.logWarning("Failed to remove temp file %s: %v", file.Name(), err)
	}
}

func (cli *Client) streamResponse(req *http.Request, res *http.Response, responseJSON interface{}) ([]byte, error) {
	file, err := ioutil.TempFile("", "mautrix-response-")
	if err != nil {
		cli.logWarning("Failed to create temporary file: %v", err)
		_, err = cli.handleNormalResponse(req, res, responseJSON)
		return nil, err
	}
	defer cli.closeTemp(file)
	if _, err = io.Copy(file, res.Body); err != nil {
		return nil, fmt.Errorf("failed to copy response to file: %w", err)
	} else if _, err = file.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("failed to seek to beginning of response file: %w", err)
	} else if err = json.NewDecoder(file).Decode(responseJSON); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response body: %w", err)
	} else {
		return nil, nil
	}
}

func (cli *Client) handleNormalResponse(req *http.Request, res *http.Response, responseJSON interface{}) ([]byte, error) {
	if contents, err := cli.readRequestBody(req, res); err != nil {
		return nil, err
	} else if responseJSON == nil {
		return contents, nil
	} else if err = json.Unmarshal(contents, &responseJSON); err != nil {
		return nil, HTTPError{
			Request:  req,
			Response: res,

			Message:      "failed to unmarshal response body",
			ResponseBody: string(contents),
			WrappedError: err,
		}
	} else {
		return contents, nil
	}
}

func (cli *Client) handleResponseError(req *http.Request, res *http.Response) ([]byte, error) {
	contents, err := cli.readRequestBody(req, res)
	if err != nil {
		return contents, err
	}

	respErr := &RespError{}
	if _ = json.Unmarshal(contents, respErr); respErr.ErrCode == "" {
		respErr = nil
	}

	return contents, HTTPError{
		Request:   req,
		Response:  res,
		RespError: respErr,
	}
}

func (cli *Client) executeCompiledRequest(req *http.Request, retries int, backoff time.Duration, responseJSON interface{}, handler ClientResponseHandler) ([]byte, error) {
	cli.LogRequest(req)
	res, err := cli.Client.Do(req)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		if retries > 0 {
			return cli.doRetry(req, err, retries, backoff, responseJSON, handler)
		}
		return nil, HTTPError{
			Request:  req,
			Response: res,

			Message:      "request error",
			WrappedError: err,
		}
	}

	if retries > 0 && (res.StatusCode == http.StatusBadGateway || res.StatusCode == http.StatusServiceUnavailable || res.StatusCode == http.StatusGatewayTimeout) {
		return cli.doRetry(req, fmt.Errorf("HTTP %d", res.StatusCode), retries, backoff, responseJSON, handler)
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return cli.handleResponseError(req, res)
	}
	return handler(req, res, responseJSON)
}

// Whoami gets the user ID of the current user. See https://matrix.org/docs/spec/client_server/r0.6.1#post-matrix-client-r0-rooms-roomid-join
func (cli *Client) Whoami() (resp *RespWhoami, err error) {
	urlPath := cli.BuildURL("account", "whoami")
	_, err = cli.MakeRequest("GET", urlPath, nil, &resp)
	return
}

// CreateFilter makes an HTTP request according to http://matrix.org/docs/spec/client_server/r0.2.0.html#post-matrix-client-r0-user-userid-filter
func (cli *Client) CreateFilter(filter *Filter) (resp *RespCreateFilter, err error) {
	urlPath := cli.BuildURL("user", cli.UserID, "filter")
	_, err = cli.MakeRequest("POST", urlPath, filter, &resp)
	return
}

// SyncRequest makes an HTTP request according to http://matrix.org/docs/spec/client_server/r0.2.0.html#get-matrix-client-r0-sync
func (cli *Client) SyncRequest(timeout int, since, filterID string, fullState bool, setPresence event.Presence, ctx context.Context) (resp *RespSync, err error) {
	return cli.FullSyncRequest(ReqSync{
		Timeout:     timeout,
		Since:       since,
		FilterID:    filterID,
		FullState:   fullState,
		SetPresence: setPresence,
		Context:     ctx,
	})
}

type ReqSync struct {
	Timeout     int
	Since       string
	FilterID    string
	FullState   bool
	SetPresence event.Presence

	Context        context.Context
	StreamResponse bool
}

func (req *ReqSync) BuildQuery() map[string]string {
	query := map[string]string{
		"timeout": strconv.Itoa(req.Timeout),
	}
	if req.Since != "" {
		query["since"] = req.Since
	}
	if req.FilterID != "" {
		query["filter"] = req.FilterID
	}
	if req.SetPresence != "" {
		query["set_presence"] = string(req.SetPresence)
	}
	if req.FullState {
		query["full_state"] = "true"
	}
	return query
}

// FullSyncRequest makes an HTTP request according to http://matrix.org/docs/spec/client_server/r0.2.0.html#get-matrix-client-r0-sync
func (cli *Client) FullSyncRequest(req ReqSync) (resp *RespSync, err error) {
	urlPath := cli.BuildURLWithQuery(URLPath{"sync"}, req.BuildQuery())
	fullReq := FullRequest{
		Method:       http.MethodGet,
		URL:          urlPath,
		ResponseJSON: &resp,
		Context:      req.Context,
		// We don't want automatic retries for SyncRequest, the Sync() wrapper handles those.
		MaxAttempts: 1,
	}
	if req.StreamResponse {
		fullReq.Handler = cli.streamResponse
	}
	start := time.Now()
	_, err = cli.MakeFullRequest(fullReq)
	duration := time.Now().Sub(start)
	timeout := time.Duration(req.Timeout) * time.Millisecond
	buffer := 10 * time.Second
	if req.Since == "" {
		buffer = 1 * time.Minute
	}
	if err == nil && duration > timeout+buffer {
		cli.logWarning("Sync request (%s) took %s with timeout %s", req.Since, duration, timeout)
	}
	return
}

func (cli *Client) register(url string, req *ReqRegister) (resp *RespRegister, uiaResp *RespUserInteractive, err error) {
	var bodyBytes []byte
	bodyBytes, err = cli.MakeFullRequest(FullRequest{
		Method:           http.MethodPost,
		URL:              url,
		RequestJSON:      req,
		SensitiveContent: len(req.Password) > 0,
	})
	if err != nil {
		httpErr, ok := err.(HTTPError)
		// if response has a 401 status, but doesn't have the errcode field, it's probably a UIA response.
		if ok && httpErr.IsStatus(http.StatusUnauthorized) && httpErr.RespError == nil {
			err = json.Unmarshal(bodyBytes, &uiaResp)
		}
	} else {
		// body should be RespRegister
		err = json.Unmarshal(bodyBytes, &resp)
	}
	return
}

// Register makes an HTTP request according to http://matrix.org/docs/spec/client_server/r0.2.0.html#post-matrix-client-r0-register
//
// Registers with kind=user. For kind=guest, see RegisterGuest.
func (cli *Client) Register(req *ReqRegister) (*RespRegister, *RespUserInteractive, error) {
	u := cli.BuildURL("register")
	return cli.register(u, req)
}

// RegisterGuest makes an HTTP request according to http://matrix.org/docs/spec/client_server/r0.2.0.html#post-matrix-client-r0-register
// with kind=guest.
//
// For kind=user, see Register.
func (cli *Client) RegisterGuest(req *ReqRegister) (*RespRegister, *RespUserInteractive, error) {
	query := map[string]string{
		"kind": "guest",
	}
	u := cli.BuildURLWithQuery(URLPath{"register"}, query)
	return cli.register(u, req)
}

// RegisterDummy performs m.login.dummy registration according to https://matrix.org/docs/spec/client_server/r0.2.0.html#dummy-auth
//
// Only a username and password need to be provided on the ReqRegister struct. Most local/developer homeservers will allow registration
// this way. If the homeserver does not, an error is returned.
//
// This does not set credentials on the client instance. See SetCredentials() instead.
//
// 	res, err := cli.RegisterDummy(&mautrix.ReqRegister{
//		Username: "alice",
//		Password: "wonderland",
//	})
//  if err != nil {
// 		panic(err)
// 	}
// 	token := res.AccessToken
func (cli *Client) RegisterDummy(req *ReqRegister) (*RespRegister, error) {
	res, uia, err := cli.Register(req)
	if err != nil && uia == nil {
		return nil, err
	} else if uia == nil {
		return nil, errors.New("server did not return user-interactive auth flows")
	} else if !uia.HasSingleStageFlow(AuthTypeDummy) {
		return nil, errors.New("server does not support m.login.dummy")
	}
	req.Auth = BaseAuthData{Type: AuthTypeDummy, Session: uia.Session}
	res, _, err = cli.Register(req)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (cli *Client) GetLoginFlows() (resp *RespLoginFlows, err error) {
	urlPath := cli.BuildURL("login")
	_, err = cli.MakeRequest("GET", urlPath, nil, &resp)
	return
}

// Login a user to the homeserver according to http://matrix.org/docs/spec/client_server/r0.2.0.html#post-matrix-client-r0-login
func (cli *Client) Login(req *ReqLogin) (resp *RespLogin, err error) {
	_, err = cli.MakeFullRequest(FullRequest{
		Method:           http.MethodPost,
		URL:              cli.BuildURL("login"),
		RequestJSON:      req,
		ResponseJSON:     &resp,
		SensitiveContent: len(req.Password) > 0 || len(req.Token) > 0,
	})
	if req.StoreCredentials && err == nil {
		cli.DeviceID = resp.DeviceID
		cli.AccessToken = resp.AccessToken
		cli.UserID = resp.UserID
		cli.Logger.Debugfln("Stored credentials for %s/%s after login", cli.UserID, cli.DeviceID)
	}
	if req.StoreHomeserverURL && err == nil && resp.WellKnown != nil && len(resp.WellKnown.Homeserver.BaseURL) > 0 {
		var urlErr error
		cli.HomeserverURL, urlErr = url.Parse(resp.WellKnown.Homeserver.BaseURL)
		if urlErr != nil {
			cli.logWarning("Failed to parse homeserver URL '%s' in login response: %v", resp.WellKnown.Homeserver.BaseURL, urlErr)
		} else {
			cli.Logger.Debugfln("Updated homeserver URL to %s after login", cli.HomeserverURL.String())
		}
	}
	return
}

// Logout the current user. See http://matrix.org/docs/spec/client_server/r0.2.0.html#post-matrix-client-r0-logout
// This does not clear the credentials from the client instance. See ClearCredentials() instead.
func (cli *Client) Logout() (resp *RespLogout, err error) {
	urlPath := cli.BuildURL("logout")
	_, err = cli.MakeRequest("POST", urlPath, nil, &resp)
	return
}

// LogoutAll logs out all the devices of the current user. See https://matrix.org/docs/spec/client_server/r0.6.1#post-matrix-client-r0-logout-all
// This does not clear the credentials from the client instance. See ClearCredentials() instead.
func (cli *Client) LogoutAll() (resp *RespLogout, err error) {
	urlPath := cli.BuildURL("logout", "all")
	_, err = cli.MakeRequest("POST", urlPath, nil, &resp)
	return
}

// Versions returns the list of supported Matrix versions on this homeserver. See http://matrix.org/docs/spec/client_server/r0.6.1.html#get-matrix-client-versions
func (cli *Client) Versions() (resp *RespVersions, err error) {
	urlPath := cli.BuildBaseURL("_matrix", "client", "versions")
	_, err = cli.MakeRequest("GET", urlPath, nil, &resp)
	return
}

// JoinRoom joins the client to a room ID or alias. See http://matrix.org/docs/spec/client_server/r0.6.1.html#post-matrix-client-r0-join-roomidoralias
//
// If serverName is specified, this will be added as a query param to instruct the homeserver to join via that server. If content is specified, it will
// be JSON encoded and used as the request body.
func (cli *Client) JoinRoom(roomIDorAlias, serverName string, content interface{}) (resp *RespJoinRoom, err error) {
	var urlPath string
	if serverName != "" {
		urlPath = cli.BuildURLWithQuery(URLPath{"join", roomIDorAlias}, map[string]string{
			"server_name": serverName,
		})
	} else {
		urlPath = cli.BuildURL("join", roomIDorAlias)
	}
	_, err = cli.MakeRequest("POST", urlPath, content, &resp)
	return
}

// JoinRoomByID joins the client to a room ID. See https://matrix.org/docs/spec/client_server/r0.6.1#post-matrix-client-r0-rooms-roomid-join
//
// Unlike JoinRoom, this method can only be used to join rooms that the server already knows about.
// It's mostly intended for bridges and other things where it's already certain that the server is in the room.
func (cli *Client) JoinRoomByID(roomID id.RoomID) (resp *RespJoinRoom, err error) {
	_, err = cli.MakeRequest("POST", cli.BuildURL("rooms", roomID, "join"), nil, &resp)
	return
}

// GetDisplayName returns the display name of the user with the specified MXID. See https://matrix.org/docs/spec/client_server/r0.6.1.html#get-matrix-client-r0-profile-userid-displayname
func (cli *Client) GetDisplayName(mxid id.UserID) (resp *RespUserDisplayName, err error) {
	urlPath := cli.BuildURL("profile", mxid, "displayname")
	_, err = cli.MakeRequest("GET", urlPath, nil, &resp)
	return
}

// GetOwnDisplayName returns the user's display name. See https://matrix.org/docs/spec/client_server/r0.6.1.html#get-matrix-client-r0-profile-userid-displayname
func (cli *Client) GetOwnDisplayName() (resp *RespUserDisplayName, err error) {
	return cli.GetDisplayName(cli.UserID)
}

// SetDisplayName sets the user's profile display name. See http://matrix.org/docs/spec/client_server/r0.6.1.html#put-matrix-client-r0-profile-userid-displayname
func (cli *Client) SetDisplayName(displayName string) (err error) {
	urlPath := cli.BuildURL("profile", cli.UserID, "displayname")
	s := struct {
		DisplayName string `json:"displayname"`
	}{displayName}
	_, err = cli.MakeRequest("PUT", urlPath, &s, nil)
	return
}

// GetAvatarURL gets the avatar URL of the user with the specified MXID. See http://matrix.org/docs/spec/client_server/r0.6.1.html#get-matrix-client-r0-profile-userid-avatar-url
func (cli *Client) GetAvatarURL(mxid id.UserID) (url id.ContentURI, err error) {
	urlPath := cli.BuildURL("profile", cli.UserID, "avatar_url")
	s := struct {
		AvatarURL id.ContentURI `json:"avatar_url"`
	}{}

	_, err = cli.MakeRequest("GET", urlPath, nil, &s)
	if err != nil {
		return
	}
	url = s.AvatarURL
	return
}

// GetOwnAvatarURL gets the user's avatar URL. See http://matrix.org/docs/spec/client_server/r0.6.1.html#get-matrix-client-r0-profile-userid-avatar-url
func (cli *Client) GetOwnAvatarURL() (url id.ContentURI, err error) {
	return cli.GetAvatarURL(cli.UserID)
}

// SetAvatarURL sets the user's avatar URL. See http://matrix.org/docs/spec/client_server/r0.6.1.html#put-matrix-client-r0-profile-userid-avatar-url
func (cli *Client) SetAvatarURL(url id.ContentURI) (err error) {
	urlPath := cli.BuildURL("profile", cli.UserID, "avatar_url")
	s := struct {
		AvatarURL string `json:"avatar_url"`
	}{url.String()}
	_, err = cli.MakeRequest("PUT", urlPath, &s, nil)
	if err != nil {
		return err
	}

	return nil
}

// GetAccountData gets the user's account data of this type. See https://matrix.org/docs/spec/client_server/r0.6.1#get-matrix-client-r0-user-userid-account-data-type
func (cli *Client) GetAccountData(name string, output interface{}) (err error) {
	urlPath := cli.BuildURL("user", cli.UserID, "account_data", name)
	_, err = cli.MakeRequest("GET", urlPath, nil, output)
	return
}

// SetAccountData sets the user's account data of this type. See https://matrix.org/docs/spec/client_server/r0.6.1#put-matrix-client-r0-user-userid-account-data-type
func (cli *Client) SetAccountData(name string, data interface{}) (err error) {
	urlPath := cli.BuildURL("user", cli.UserID, "account_data", name)
	_, err = cli.MakeRequest("PUT", urlPath, &data, nil)
	if err != nil {
		return err
	}

	return nil
}

func (cli *Client) GetRoomAccountData(roomID id.RoomID, name string, output interface{}) (err error) {
	urlPath := cli.BuildURL("user", cli.UserID, "rooms", roomID, "account_data", name)
	_, err = cli.MakeRequest("GET", urlPath, nil, output)
	return
}

func (cli *Client) SetRoomAccountData(roomID id.RoomID, name string, data interface{}) (err error) {
	urlPath := cli.BuildURL("user", cli.UserID, "rooms", roomID, "account_data", name)
	_, err = cli.MakeRequest("PUT", urlPath, &data, nil)
	if err != nil {
		return err
	}

	return nil
}

type ReqSendEvent struct {
	Timestamp     int64
	TransactionID string

	ParentID string
	RelType  event.RelationType
}

// SendMessageEvent sends a message event into a room. See http://matrix.org/docs/spec/client_server/r0.2.0.html#put-matrix-client-r0-rooms-roomid-send-eventtype-txnid
// contentJSON should be a pointer to something that can be encoded as JSON using json.Marshal.
func (cli *Client) SendMessageEvent(roomID id.RoomID, eventType event.Type, contentJSON interface{}, extra ...ReqSendEvent) (resp *RespSendEvent, err error) {
	var req ReqSendEvent
	if len(extra) > 0 {
		req = extra[0]
	}

	var txnID string
	if len(req.TransactionID) > 0 {
		txnID = req.TransactionID
	} else {
		txnID = cli.TxnID()
	}

	queryParams := map[string]string{}
	if req.Timestamp > 0 {
		queryParams["ts"] = strconv.FormatInt(req.Timestamp, 10)
	}

	urlData := URLPath{"rooms", roomID, "send", eventType.String(), txnID}
	if len(req.ParentID) > 0 {
		urlData = URLPath{"rooms", roomID, "send_relation", req.ParentID, req.RelType, eventType.String(), txnID}
	}

	urlPath := cli.BuildURLWithQuery(urlData, queryParams)
	_, err = cli.MakeRequest("PUT", urlPath, contentJSON, &resp)
	return
}

// SendStateEvent sends a state event into a room. See http://matrix.org/docs/spec/client_server/r0.2.0.html#put-matrix-client-r0-rooms-roomid-state-eventtype-statekey
// contentJSON should be a pointer to something that can be encoded as JSON using json.Marshal.
func (cli *Client) SendStateEvent(roomID id.RoomID, eventType event.Type, stateKey string, contentJSON interface{}) (resp *RespSendEvent, err error) {
	urlPath := cli.BuildURL("rooms", roomID, "state", eventType.String(), stateKey)
	_, err = cli.MakeRequest("PUT", urlPath, contentJSON, &resp)
	return
}

// SendStateEvent sends a state event into a room. See http://matrix.org/docs/spec/client_server/r0.2.0.html#put-matrix-client-r0-rooms-roomid-state-eventtype-statekey
// contentJSON should be a pointer to something that can be encoded as JSON using json.Marshal.
func (cli *Client) SendMassagedStateEvent(roomID id.RoomID, eventType event.Type, stateKey string, contentJSON interface{}, ts int64) (resp *RespSendEvent, err error) {
	urlPath := cli.BuildURLWithQuery(URLPath{"rooms", roomID, "state", eventType.String(), stateKey}, map[string]string{
		"ts": strconv.FormatInt(ts, 10),
	})
	_, err = cli.MakeRequest("PUT", urlPath, contentJSON, &resp)
	return
}

// SendText sends an m.room.message event into the given room with a msgtype of m.text
// See http://matrix.org/docs/spec/client_server/r0.2.0.html#m-text
func (cli *Client) SendText(roomID id.RoomID, text string) (*RespSendEvent, error) {
	return cli.SendMessageEvent(roomID, event.EventMessage, &event.MessageEventContent{
		MsgType: event.MsgText,
		Body:    text,
	})
}

// SendImage sends an m.room.message event into the given room with a msgtype of m.image
// See https://matrix.org/docs/spec/client_server/r0.2.0.html#m-image
func (cli *Client) SendImage(roomID id.RoomID, body string, url id.ContentURI) (*RespSendEvent, error) {
	return cli.SendMessageEvent(roomID, event.EventMessage, &event.MessageEventContent{
		MsgType: event.MsgImage,
		Body:    body,
		URL:     url.CUString(),
	})
}

// SendVideo sends an m.room.message event into the given room with a msgtype of m.video
// See https://matrix.org/docs/spec/client_server/r0.2.0.html#m-video
func (cli *Client) SendVideo(roomID id.RoomID, body string, url id.ContentURI) (*RespSendEvent, error) {
	return cli.SendMessageEvent(roomID, event.EventMessage, &event.MessageEventContent{
		MsgType: event.MsgVideo,
		Body:    body,
		URL:     url.CUString(),
	})
}

// SendNotice sends an m.room.message event into the given room with a msgtype of m.notice
// See http://matrix.org/docs/spec/client_server/r0.2.0.html#m-notice
func (cli *Client) SendNotice(roomID id.RoomID, text string) (*RespSendEvent, error) {
	return cli.SendMessageEvent(roomID, event.EventMessage, &event.MessageEventContent{
		MsgType: event.MsgNotice,
		Body:    text,
	})
}

func (cli *Client) SendReaction(roomID id.RoomID, eventID id.EventID, reaction string) (*RespSendEvent, error) {
	return cli.SendMessageEvent(roomID, event.EventReaction, &event.ReactionEventContent{
		RelatesTo: event.RelatesTo{
			EventID: eventID,
			Type:    event.RelAnnotation,
			Key:     reaction,
		},
	})
}

// RedactEvent redacts the given event. See http://matrix.org/docs/spec/client_server/r0.2.0.html#put-matrix-client-r0-rooms-roomid-redact-eventid-txnid
func (cli *Client) RedactEvent(roomID id.RoomID, eventID id.EventID, extra ...ReqRedact) (resp *RespSendEvent, err error) {
	req := ReqRedact{}
	if len(extra) > 0 {
		req = extra[0]
	}
	if req.Extra == nil {
		req.Extra = make(map[string]interface{})
	}
	if len(req.Reason) > 0 {
		req.Extra["reason"] = req.Reason
	}
	var txnID string
	if len(req.TxnID) > 0 {
		txnID = req.TxnID
	} else {
		txnID = cli.TxnID()
	}
	urlPath := cli.BuildURL("rooms", roomID, "redact", eventID, txnID)
	_, err = cli.MakeRequest("PUT", urlPath, req.Extra, &resp)
	return
}

// CreateRoom creates a new Matrix room. See https://matrix.org/docs/spec/client_server/r0.2.0.html#post-matrix-client-r0-createroom
//  resp, err := cli.CreateRoom(&mautrix.ReqCreateRoom{
//  	Preset: "public_chat",
//  })
//  fmt.Println("Room:", resp.RoomID)
func (cli *Client) CreateRoom(req *ReqCreateRoom) (resp *RespCreateRoom, err error) {
	urlPath := cli.BuildURL("createRoom")
	_, err = cli.MakeRequest("POST", urlPath, req, &resp)
	return
}

// LeaveRoom leaves the given room. See http://matrix.org/docs/spec/client_server/r0.2.0.html#post-matrix-client-r0-rooms-roomid-leave
func (cli *Client) LeaveRoom(roomID id.RoomID, optionalReq ...*ReqLeave) (resp *RespLeaveRoom, err error) {
	req := &ReqLeave{}
	if len(optionalReq) == 1 {
		req = optionalReq[0]
	} else if len(optionalReq) > 1 {
		panic("invalid number of arguments to LeaveRoom")
	}
	u := cli.BuildURL("rooms", roomID, "leave")
	_, err = cli.MakeRequest("POST", u, req, &resp)
	return
}

// ForgetRoom forgets a room entirely. See http://matrix.org/docs/spec/client_server/r0.2.0.html#post-matrix-client-r0-rooms-roomid-forget
func (cli *Client) ForgetRoom(roomID id.RoomID) (resp *RespForgetRoom, err error) {
	u := cli.BuildURL("rooms", roomID, "forget")
	_, err = cli.MakeRequest("POST", u, struct{}{}, &resp)
	return
}

// InviteUser invites a user to a room. See http://matrix.org/docs/spec/client_server/r0.2.0.html#post-matrix-client-r0-rooms-roomid-invite
func (cli *Client) InviteUser(roomID id.RoomID, req *ReqInviteUser) (resp *RespInviteUser, err error) {
	u := cli.BuildURL("rooms", roomID, "invite")
	_, err = cli.MakeRequest("POST", u, req, &resp)
	return
}

// InviteUserByThirdParty invites a third-party identifier to a room. See http://matrix.org/docs/spec/client_server/r0.2.0.html#invite-by-third-party-id-endpoint
func (cli *Client) InviteUserByThirdParty(roomID id.RoomID, req *ReqInvite3PID) (resp *RespInviteUser, err error) {
	u := cli.BuildURL("rooms", roomID, "invite")
	_, err = cli.MakeRequest("POST", u, req, &resp)
	return
}

// KickUser kicks a user from a room. See http://matrix.org/docs/spec/client_server/r0.2.0.html#post-matrix-client-r0-rooms-roomid-kick
func (cli *Client) KickUser(roomID id.RoomID, req *ReqKickUser) (resp *RespKickUser, err error) {
	u := cli.BuildURL("rooms", roomID, "kick")
	_, err = cli.MakeRequest("POST", u, req, &resp)
	return
}

// BanUser bans a user from a room. See http://matrix.org/docs/spec/client_server/r0.2.0.html#post-matrix-client-r0-rooms-roomid-ban
func (cli *Client) BanUser(roomID id.RoomID, req *ReqBanUser) (resp *RespBanUser, err error) {
	u := cli.BuildURL("rooms", roomID, "ban")
	_, err = cli.MakeRequest("POST", u, req, &resp)
	return
}

// UnbanUser unbans a user from a room. See http://matrix.org/docs/spec/client_server/r0.2.0.html#post-matrix-client-r0-rooms-roomid-unban
func (cli *Client) UnbanUser(roomID id.RoomID, req *ReqUnbanUser) (resp *RespUnbanUser, err error) {
	u := cli.BuildURL("rooms", roomID, "unban")
	_, err = cli.MakeRequest("POST", u, req, &resp)
	return
}

// UserTyping sets the typing status of the user. See https://matrix.org/docs/spec/client_server/r0.2.0.html#put-matrix-client-r0-rooms-roomid-typing-userid
func (cli *Client) UserTyping(roomID id.RoomID, typing bool, timeout int64) (resp *RespTyping, err error) {
	req := ReqTyping{Typing: typing, Timeout: timeout}
	u := cli.BuildURL("rooms", roomID, "typing", cli.UserID)
	_, err = cli.MakeRequest("PUT", u, req, &resp)
	return
}

// GetPresence gets the presence of the user with the specified MXID. See https://matrix.org/docs/spec/client_server/r0.6.1#get-matrix-client-r0-presence-userid-status
func (cli *Client) GetPresence(userID id.UserID) (resp *RespPresence, err error) {
	resp = new(RespPresence)
	u := cli.BuildURL("presence", userID, "status")
	_, err = cli.MakeRequest("GET", u, nil, resp)
	return
}

// GetOwnPresence gets the user's presence. See https://matrix.org/docs/spec/client_server/r0.6.1#get-matrix-client-r0-presence-userid-status
func (cli *Client) GetOwnPresence() (resp *RespPresence, err error) {
	return cli.GetPresence(cli.UserID)
}

func (cli *Client) SetPresence(status event.Presence) (err error) {
	req := ReqPresence{Presence: status}
	u := cli.BuildURL("presence", cli.UserID, "status")
	_, err = cli.MakeRequest("PUT", u, req, nil)
	return
}

// StateEvent gets a single state event in a room. It will attempt to JSON unmarshal into the given "outContent" struct with
// the HTTP response body, or return an error.
// See http://matrix.org/docs/spec/client_server/r0.2.0.html#get-matrix-client-r0-rooms-roomid-state-eventtype-statekey
func (cli *Client) StateEvent(roomID id.RoomID, eventType event.Type, stateKey string, outContent interface{}) (err error) {
	u := cli.BuildURL("rooms", roomID, "state", eventType.String(), stateKey)
	_, err = cli.MakeRequest("GET", u, nil, outContent)
	return
}

// parseRoomStateArray parses a JSON array as a stream and stores the events inside it in a room state map.
func parseRoomStateArray(_ *http.Request, res *http.Response, responseJSON interface{}) ([]byte, error) {
	response := make(RoomStateMap)
	responsePtr := responseJSON.(*map[event.Type]map[string]*event.Event)
	*responsePtr = response
	dec := json.NewDecoder(res.Body)

	arrayStart, err := dec.Token()
	if err != nil {
		return nil, err
	} else if arrayStart != json.Delim('[') {
		return nil, fmt.Errorf("expected array start, got %+v", arrayStart)
	}

	for i := 1; dec.More(); i++ {
		var evt *event.Event
		err = dec.Decode(&evt)
		if err != nil {
			return nil, fmt.Errorf("failed to parse state array item #%d: %v", i, err)
		}
		_ = evt.Content.ParseRaw(evt.Type)
		subMap, ok := response[evt.Type]
		if !ok {
			subMap = make(map[string]*event.Event)
			response[evt.Type] = subMap
		}
		subMap[*evt.StateKey] = evt
	}

	arrayEnd, err := dec.Token()
	if err != nil {
		return nil, err
	} else if arrayEnd != json.Delim(']') {
		return nil, fmt.Errorf("expected array end, got %+v", arrayStart)
	}
	return nil, nil
}

// State gets all state in a room.
// See https://matrix.org/docs/spec/client_server/r0.6.1#get-matrix-client-r0-rooms-roomid-state
func (cli *Client) State(roomID id.RoomID) (stateMap RoomStateMap, err error) {
	_, err = cli.MakeFullRequest(FullRequest{
		Method:       http.MethodGet,
		URL:          cli.BuildURL("rooms", roomID, "state"),
		ResponseJSON: &stateMap,
		Handler:      parseRoomStateArray,
	})
	return
}

// UploadLink uploads an HTTP URL and then returns an MXC URI.
func (cli *Client) UploadLink(link string) (*RespMediaUpload, error) {
	res, err := cli.Client.Get(link)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return cli.Upload(res.Body, res.Header.Get("Content-Type"), res.ContentLength)
}

func (cli *Client) GetDownloadURL(mxcURL id.ContentURI) string {
	return cli.BuildBaseURL("_matrix", "media", "r0", "download", mxcURL.Homeserver, mxcURL.FileID)
}

func (cli *Client) Download(mxcURL id.ContentURI) (io.ReadCloser, error) {
	resp, err := cli.Client.Get(cli.GetDownloadURL(mxcURL))
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func (cli *Client) DownloadBytes(mxcURL id.ContentURI) ([]byte, error) {
	resp, err := cli.Download(mxcURL)
	if err != nil {
		return nil, err
	}
	defer resp.Close()
	return ioutil.ReadAll(resp)
}

// UnstableCreateMXC creates a blank Matrix content URI to allow uploading the content asynchronously later.
// See https://github.com/matrix-org/matrix-spec-proposals/pull/2246
func (cli *Client) UnstableCreateMXC() (*RespCreateMXC, error) {
	u, _ := url.Parse(cli.BuildBaseURL("_matrix", "media", "unstable", "fi.mau.msc2246", "create"))
	var m RespCreateMXC
	_, err := cli.MakeFullRequest(FullRequest{
		Method:       http.MethodPost,
		URL:          u.String(),
		ResponseJSON: &m,
	})
	return &m, err
}

// UnstableUploadAsync creates a blank content URI with UnstableCreateMXC, starts uploading the data in the background
// and returns the created MXC immediately. See https://github.com/matrix-org/matrix-spec-proposals/pull/2246 for more info.
func (cli *Client) UnstableUploadAsync(req ReqUploadMedia) (*RespCreateMXC, error) {
	resp, err := cli.UnstableCreateMXC()
	if err != nil {
		return nil, err
	}
	req.UnstableMXC = resp.ContentURI
	go func() {
		_, err = cli.UploadMedia(req)
		if err != nil {
			cli.logWarning("Failed to upload %s: %v", req.UnstableMXC, err)
		}
	}()
	return resp, nil
}

func (cli *Client) UploadBytes(data []byte, contentType string) (*RespMediaUpload, error) {
	return cli.UploadBytesWithName(data, contentType, "")
}

func (cli *Client) UploadBytesWithName(data []byte, contentType, fileName string) (*RespMediaUpload, error) {
	return cli.UploadMedia(ReqUploadMedia{
		ContentBytes: data,
		ContentType:  contentType,
		FileName:     fileName,
	})
}

// Upload uploads the given data to the content repository and returns an MXC URI.
//
// Deprecated: UploadMedia should be used instead.
func (cli *Client) Upload(content io.Reader, contentType string, contentLength int64) (*RespMediaUpload, error) {
	return cli.UploadMedia(ReqUploadMedia{
		Content:       content,
		ContentLength: contentLength,
		ContentType:   contentType,
	})
}

type ReqUploadMedia struct {
	ContentBytes  []byte
	Content       io.Reader
	ContentLength int64
	ContentType   string
	FileName      string

	// UnstableMXC specifies an existing MXC URI which doesn't have content yet to upload into.
	// See https://github.com/matrix-org/matrix-spec-proposals/pull/2246 for more info.
	UnstableMXC id.ContentURI
}

// UploadMedia uploads the given data to the content repository and returns an MXC URI.
// See https://spec.matrix.org/v1.2/client-server-api/#post_matrixmediav3upload
func (cli *Client) UploadMedia(data ReqUploadMedia) (*RespMediaUpload, error) {
	u, _ := url.Parse(cli.BuildBaseURL("_matrix", "media", "r0", "upload"))
	method := http.MethodPost
	if !data.UnstableMXC.IsEmpty() {
		u, _ = url.Parse(cli.BuildBaseURL("_matrix", "media", "unstable", "fi.mau.msc2246", "upload", data.UnstableMXC.Homeserver, data.UnstableMXC.FileID))
		method = http.MethodPut
	}
	if len(data.FileName) > 0 {
		q := u.Query()
		q.Set("filename", data.FileName)
		u.RawQuery = q.Encode()
	}

	var headers http.Header
	if len(data.ContentType) > 0 {
		headers = http.Header{"Content-Type": []string{data.ContentType}}
	}

	var m RespMediaUpload
	_, err := cli.MakeFullRequest(FullRequest{
		Method:        method,
		URL:           u.String(),
		Headers:       headers,
		RequestBytes:  data.ContentBytes,
		RequestBody:   data.Content,
		RequestLength: data.ContentLength,
		ResponseJSON:  &m,
	})
	return &m, err
}

// GetURLPreview asks the homeserver to fetch a preview for a given URL.
//
// See https://spec.matrix.org/v1.2/client-server-api/#get_matrixmediav3preview_url
func (cli *Client) GetURLPreview(url string) (*RespPreviewURL, error) {
	reqURL := cli.BuildBaseURLWithQuery(URLPath{"_matrix", "media", "r0", "preview_url"}, map[string]string{
		"url": url,
	})
	var output RespPreviewURL
	_, err := cli.MakeRequest(http.MethodGet, reqURL, nil, &output)
	return &output, err
}

// JoinedMembers returns a map of joined room members. See https://matrix.org/docs/spec/client_server/r0.4.0.html#get-matrix-client-r0-joined-rooms
//
// In general, usage of this API is discouraged in favour of /sync, as calling this API can race with incoming membership changes.
// This API is primarily designed for application services which may want to efficiently look up joined members in a room.
func (cli *Client) JoinedMembers(roomID id.RoomID) (resp *RespJoinedMembers, err error) {
	u := cli.BuildURL("rooms", roomID, "joined_members")
	_, err = cli.MakeRequest("GET", u, nil, &resp)
	return
}

func (cli *Client) Members(roomID id.RoomID, req ...ReqMembers) (resp *RespMembers, err error) {
	var extra ReqMembers
	if len(req) > 0 {
		extra = req[0]
	}
	query := map[string]string{}
	if len(extra.At) > 0 {
		query["at"] = extra.At
	}
	if len(extra.Membership) > 0 {
		query["membership"] = string(extra.Membership)
	}
	if len(extra.NotMembership) > 0 {
		query["not_membership"] = string(extra.NotMembership)
	}
	u := cli.BuildURLWithQuery(URLPath{"rooms", roomID, "members"}, query)
	_, err = cli.MakeRequest("GET", u, nil, &resp)
	return
}

// JoinedRooms returns a list of rooms which the client is joined to. See https://matrix.org/docs/spec/client_server/r0.4.0.html#get-matrix-client-r0-joined-rooms
//
// In general, usage of this API is discouraged in favour of /sync, as calling this API can race with incoming membership changes.
// This API is primarily designed for application services which may want to efficiently look up joined rooms.
func (cli *Client) JoinedRooms() (resp *RespJoinedRooms, err error) {
	u := cli.BuildURL("joined_rooms")
	_, err = cli.MakeRequest("GET", u, nil, &resp)
	return
}

// Messages returns a list of message and state events for a room. It uses
// pagination query parameters to paginate history in the room.
// See https://matrix.org/docs/spec/client_server/r0.2.0.html#get-matrix-client-r0-rooms-roomid-messages
func (cli *Client) Messages(roomID id.RoomID, from, to string, dir rune, filter *FilterPart, limit int) (resp *RespMessages, err error) {
	query := map[string]string{
		"from": from,
		"dir":  string(dir),
	}
	if filter != nil {
		filterJSON, err := json.Marshal(filter)
		if err != nil {
			return nil, err
		}
		query["filter"] = string(filterJSON)
	}
	if to != "" {
		query["to"] = to
	}
	if limit != 0 {
		query["limit"] = strconv.Itoa(limit)
	}

	urlPath := cli.BuildURLWithQuery(URLPath{"rooms", roomID, "messages"}, query)
	_, err = cli.MakeRequest("GET", urlPath, nil, &resp)
	return
}

// Context returns a number of events that happened just before and after the
// specified event. It use pagination query parameters to paginate history in
// the room.
// See https://spec.matrix.org/v1.1/client-server-api/#get_matrixclientv3roomsroomidcontexteventid
func (cli *Client) Context(roomID id.RoomID, eventID id.EventID, filter *FilterPart, limit int) (resp *RespContext, err error) {
	query := map[string]string{}
	if filter != nil {
		filterJSON, err := json.Marshal(filter)
		if err != nil {
			return nil, err
		}
		query["filter"] = string(filterJSON)
	}
	if limit != 0 {
		query["limit"] = strconv.Itoa(limit)
	}

	urlPath := cli.BuildURLWithQuery(URLPath{"rooms", roomID, "context", eventID}, query)
	_, err = cli.MakeRequest("GET", urlPath, nil, &resp)
	return
}

func (cli *Client) GetEvent(roomID id.RoomID, eventID id.EventID) (resp *event.Event, err error) {
	urlPath := cli.BuildURL("rooms", roomID, "event", eventID)
	_, err = cli.MakeRequest("GET", urlPath, nil, &resp)
	return
}

func (cli *Client) MarkRead(roomID id.RoomID, eventID id.EventID) (err error) {
	return cli.MarkReadWithContent(roomID, eventID, struct{}{})
}

// MarkReadWithContent sends a read receipt including custom data.
// N.B. This is not (yet) a part of the spec, normal servers will drop any extra content.
func (cli *Client) MarkReadWithContent(roomID id.RoomID, eventID id.EventID, content interface{}) (err error) {
	urlPath := cli.BuildURL("rooms", roomID, "receipt", "m.read", eventID)
	_, err = cli.MakeRequest("POST", urlPath, &content, nil)
	return
}

func (cli *Client) SetReadMarkers(roomID id.RoomID, content interface{}) (err error) {
	urlPath := cli.BuildURL("rooms", roomID, "read_markers")
	_, err = cli.MakeRequest("POST", urlPath, &content, nil)
	return
}

func (cli *Client) AddTag(roomID id.RoomID, tag string, order float64) error {
	var tagData event.Tag
	if order == order {
		tagData.Order = json.Number(strconv.FormatFloat(order, 'e', -1, 64))
	}
	return cli.AddTagWithCustomData(roomID, tag, tagData)
}

func (cli *Client) AddTagWithCustomData(roomID id.RoomID, tag string, data interface{}) (err error) {
	urlPath := cli.BuildURL("user", cli.UserID, "rooms", roomID, "tags", tag)
	_, err = cli.MakeRequest("PUT", urlPath, data, nil)
	return
}

func (cli *Client) GetTags(roomID id.RoomID) (tags event.TagEventContent, err error) {
	err = cli.GetTagsWithCustomData(roomID, &tags)
	return
}

func (cli *Client) GetTagsWithCustomData(roomID id.RoomID, resp interface{}) (err error) {
	urlPath := cli.BuildURL("user", cli.UserID, "rooms", roomID, "tags")
	_, err = cli.MakeRequest("GET", urlPath, nil, &resp)
	return
}

func (cli *Client) RemoveTag(roomID id.RoomID, tag string) (err error) {
	urlPath := cli.BuildURL("user", cli.UserID, "rooms", roomID, "tags", tag)
	_, err = cli.MakeRequest("DELETE", urlPath, nil, nil)
	return
}

// Deprecated: Synapse may not handle setting m.tag directly properly, so you should use the Add/RemoveTag methods instead.
func (cli *Client) SetTags(roomID id.RoomID, tags event.Tags) (err error) {
	return cli.SetRoomAccountData(roomID, "m.tag", map[string]event.Tags{
		"tags": tags,
	})
}

// TurnServer returns turn server details and credentials for the client to use when initiating calls.
// See http://matrix.org/docs/spec/client_server/r0.2.0.html#get-matrix-client-r0-voip-turnserver
func (cli *Client) TurnServer() (resp *RespTurnServer, err error) {
	urlPath := cli.BuildURL("voip", "turnServer")
	_, err = cli.MakeRequest("GET", urlPath, nil, &resp)
	return
}

func (cli *Client) CreateAlias(alias id.RoomAlias, roomID id.RoomID) (resp *RespAliasCreate, err error) {
	urlPath := cli.BuildURL("directory", "room", alias)
	_, err = cli.MakeRequest("PUT", urlPath, &ReqAliasCreate{RoomID: roomID}, &resp)
	return
}

func (cli *Client) ResolveAlias(alias id.RoomAlias) (resp *RespAliasResolve, err error) {
	urlPath := cli.BuildURL("directory", "room", alias)
	_, err = cli.MakeRequest("GET", urlPath, nil, &resp)
	return
}

func (cli *Client) DeleteAlias(alias id.RoomAlias) (resp *RespAliasDelete, err error) {
	urlPath := cli.BuildURL("directory", "room", alias)
	_, err = cli.MakeRequest("DELETE", urlPath, nil, &resp)
	return
}

func (cli *Client) GetAliases(roomID id.RoomID) (resp *RespAliasList, err error) {
	urlPath := cli.BuildURL("rooms", roomID, "aliases")
	_, err = cli.MakeRequest("GET", urlPath, nil, &resp)
	return
}

func (cli *Client) UploadKeys(req *ReqUploadKeys) (resp *RespUploadKeys, err error) {
	urlPath := cli.BuildURL("keys", "upload")
	_, err = cli.MakeRequest("POST", urlPath, req, &resp)
	return
}

func (cli *Client) QueryKeys(req *ReqQueryKeys) (resp *RespQueryKeys, err error) {
	urlPath := cli.BuildURL("keys", "query")
	_, err = cli.MakeRequest("POST", urlPath, req, &resp)
	return
}

func (cli *Client) ClaimKeys(req *ReqClaimKeys) (resp *RespClaimKeys, err error) {
	urlPath := cli.BuildURL("keys", "claim")
	_, err = cli.MakeRequest("POST", urlPath, req, &resp)
	return
}

func (cli *Client) GetKeyChanges(from, to string) (resp *RespKeyChanges, err error) {
	urlPath := cli.BuildURLWithQuery(URLPath{"keys", "changes"}, map[string]string{
		"from": from,
		"to":   to,
	})
	_, err = cli.MakeRequest("POST", urlPath, nil, &resp)
	return
}

func (cli *Client) SendToDevice(eventType event.Type, req *ReqSendToDevice) (resp *RespSendToDevice, err error) {
	urlPath := cli.BuildURL("sendToDevice", eventType.String(), cli.TxnID())
	_, err = cli.MakeRequest("PUT", urlPath, req, &resp)
	return
}

func (cli *Client) GetDevicesInfo() (resp *RespDevicesInfo, err error) {
	urlPath := cli.BuildURL("devices")
	_, err = cli.MakeRequest("GET", urlPath, nil, &resp)
	return
}

func (cli *Client) GetDeviceInfo(deviceID id.DeviceID) (resp *RespDeviceInfo, err error) {
	urlPath := cli.BuildURL("devices", deviceID)
	_, err = cli.MakeRequest("GET", urlPath, nil, &resp)
	return
}

func (cli *Client) SetDeviceInfo(deviceID id.DeviceID, req *ReqDeviceInfo) error {
	urlPath := cli.BuildURL("devices", deviceID)
	_, err := cli.MakeRequest("PUT", urlPath, req, nil)
	return err
}

func (cli *Client) DeleteDevice(deviceID id.DeviceID, req *ReqDeleteDevice) error {
	urlPath := cli.BuildURL("devices", deviceID)
	_, err := cli.MakeRequest("DELETE", urlPath, req, nil)
	return err
}

func (cli *Client) DeleteDevices(req *ReqDeleteDevices) error {
	urlPath := cli.BuildURL("delete_devices")
	_, err := cli.MakeRequest("DELETE", urlPath, req, nil)
	return err
}

type UIACallback = func(*RespUserInteractive) interface{}

// UploadCrossSigningKeys uploads the given cross-signing keys to the server.
// Because the endpoint requires user-interactive authentication a callback must be provided that,
// given the UI auth parameters, produces the required result (or nil to end the flow).
func (cli *Client) UploadCrossSigningKeys(keys *UploadCrossSigningKeysReq, uiaCallback UIACallback) error {
	content, err := cli.MakeFullRequest(FullRequest{
		Method:           http.MethodPost,
		URL:              cli.BuildBaseURL("_matrix", "client", "unstable", "keys", "device_signing", "upload"),
		RequestJSON:      keys,
		SensitiveContent: keys.Auth != nil,
	})
	if respErr, ok := err.(HTTPError); ok && respErr.IsStatus(http.StatusUnauthorized) {
		// try again with UI auth
		var uiAuthResp RespUserInteractive
		if err := json.Unmarshal(content, &uiAuthResp); err != nil {
			return fmt.Errorf("failed to decode UIA response: %w", err)
		}
		auth := uiaCallback(&uiAuthResp)
		if auth != nil {
			keys.Auth = auth
			return cli.UploadCrossSigningKeys(keys, uiaCallback)
		}
	}
	return err
}

func (cli *Client) UploadSignatures(req *ReqUploadSignatures) (resp *RespUploadSignatures, err error) {
	urlPath := cli.BuildBaseURL("_matrix", "client", "unstable", "keys", "signatures", "upload")
	_, err = cli.MakeRequest("POST", urlPath, req, &resp)
	return
}

// GetPushRules returns the push notification rules for the global scope.
func (cli *Client) GetPushRules() (*pushrules.PushRuleset, error) {
	return cli.GetScopedPushRules("global")
}

// GetScopedPushRules returns the push notification rules for the given scope.
func (cli *Client) GetScopedPushRules(scope string) (resp *pushrules.PushRuleset, err error) {
	u, _ := url.Parse(cli.BuildURL("pushrules", scope))
	// client.BuildURL returns the URL without a trailing slash, but the pushrules endpoint requires the slash.
	u.Path += "/"
	_, err = cli.MakeRequest("GET", u.String(), nil, &resp)
	return
}

func (cli *Client) GetPushRule(scope string, kind pushrules.PushRuleType, ruleID string) (resp *pushrules.PushRule, err error) {
	urlPath := cli.BuildURL("pushrules", scope, kind, ruleID)
	_, err = cli.MakeRequest("GET", urlPath, nil, &resp)
	if resp != nil {
		resp.Type = kind
	}
	return
}

func (cli *Client) DeletePushRule(scope string, kind pushrules.PushRuleType, ruleID string) error {
	urlPath := cli.BuildURL("pushrules", scope, kind, ruleID)
	_, err := cli.MakeRequest("DELETE", urlPath, nil, nil)
	return err
}

func (cli *Client) PutPushRule(scope string, kind pushrules.PushRuleType, ruleID string, req *ReqPutPushRule) error {
	query := make(map[string]string)
	if len(req.After) > 0 {
		query["after"] = req.After
	}
	if len(req.Before) > 0 {
		query["before"] = req.Before
	}
	urlPath := cli.BuildURLWithQuery(URLPath{"pushrules", scope, kind, ruleID}, query)
	_, err := cli.MakeRequest("PUT", urlPath, req, nil)
	return err
}

// BatchSend sends a batch of historical events into a room. This is only available for appservices.
//
// See https://github.com/matrix-org/matrix-doc/pull/2716 for more info.
func (cli *Client) BatchSend(roomID id.RoomID, req *ReqBatchSend) (resp *RespBatchSend, err error) {
	path := URLPath{"_matrix", "client", "unstable", "org.matrix.msc2716", "rooms", roomID, "batch_send"}
	query := map[string]string{
		"prev_event_id": req.PrevEventID.String(),
	}
	if len(req.BatchID) > 0 {
		query["batch_id"] = req.BatchID.String()
	}
	_, err = cli.MakeRequest("POST", cli.BuildBaseURLWithQuery(path, query), req, &resp)
	return
}

// TxnID returns the next transaction ID.
func (cli *Client) TxnID() string {
	txnID := atomic.AddInt32(&cli.txnID, 1)
	return fmt.Sprintf("mautrix-go_%d_%d", time.Now().UnixNano(), txnID)
}

// NewClient creates a new Matrix Client ready for syncing
func NewClient(homeserverURL string, userID id.UserID, accessToken string) (*Client, error) {
	hsURL, err := url.Parse(homeserverURL)
	if err != nil {
		return nil, err
	}
	if hsURL.Scheme == "" {
		hsURL.Scheme = "https"
	}
	return &Client{
		AccessToken:   accessToken,
		UserAgent:     DefaultUserAgent,
		HomeserverURL: hsURL,
		UserID:        userID,
		Client:        &http.Client{Timeout: 180 * time.Second},
		Prefix:        URLPath{"_matrix", "client", "r0"},
		Syncer:        NewDefaultSyncer(),
		Logger:        stubLogger,
		// By default, use an in-memory store which will never save filter ids / next batch tokens to disk.
		// The client will work with this storer: it just won't remember across restarts.
		// In practice, a database backend should be used.
		Store: NewInMemoryStore(),
	}, nil
}
