// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"go.mau.fi/util/exslices"
	"go.mau.fi/util/jsontime"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
)

type Client struct {
	HTTP       *http.Client
	ServerName string
	UserAgent  string
	Key        *SigningKey
}

func NewClient(serverName string, key *SigningKey, cache ResolutionCache) *Client {
	return &Client{
		HTTP: &http.Client{
			Transport: NewServerResolvingTransport(cache),
			Timeout:   120 * time.Second,
		},
		UserAgent:  mautrix.DefaultUserAgent,
		ServerName: serverName,
		Key:        key,
	}
}

func (c *Client) Version(ctx context.Context, serverName string) (resp *RespServerVersion, err error) {
	err = c.MakeRequest(ctx, serverName, false, http.MethodGet, URLPath{"v1", "version"}, nil, &resp)
	return
}

func (c *Client) ServerKeys(ctx context.Context, serverName string) (resp *ServerKeyResponse, err error) {
	err = c.MakeRequest(ctx, serverName, false, http.MethodGet, KeyURLPath{"v2", "server"}, nil, &resp)
	return
}

func (c *Client) QueryKeys(ctx context.Context, serverName string, req *ReqQueryKeys) (resp *QueryKeysResponse, err error) {
	err = c.MakeRequest(ctx, serverName, false, http.MethodPost, KeyURLPath{"v2", "query"}, req, &resp)
	return
}

type PDU = json.RawMessage
type EDU = json.RawMessage

type ReqSendTransaction struct {
	Destination string `json:"destination"`
	TxnID       string `json:"-"`

	Origin         string             `json:"origin"`
	OriginServerTS jsontime.UnixMilli `json:"origin_server_ts"`
	PDUs           []PDU              `json:"pdus"`
	EDUs           []EDU              `json:"edus,omitempty"`
}

type PDUProcessingResult struct {
	Error string `json:"error,omitempty"`
}

type RespSendTransaction struct {
	PDUs map[id.EventID]PDUProcessingResult `json:"pdus"`
}

func (c *Client) SendTransaction(ctx context.Context, req *ReqSendTransaction) (resp *RespSendTransaction, err error) {
	err = c.MakeRequest(ctx, req.Destination, true, http.MethodPost, URLPath{"v1", "send", req.TxnID}, req, &resp)
	return
}

type RespGetEventAuthChain struct {
	AuthChain []PDU `json:"auth_chain"`
}

func (c *Client) GetEventAuthChain(ctx context.Context, serverName string, roomID id.RoomID, eventID id.EventID) (resp *RespGetEventAuthChain, err error) {
	err = c.MakeRequest(ctx, serverName, true, http.MethodGet, URLPath{"v1", "event_auth", roomID, eventID}, nil, &resp)
	return
}

type ReqBackfill struct {
	ServerName   string
	RoomID       id.RoomID
	Limit        int
	BackfillFrom []id.EventID
}

type RespBackfill struct {
	Origin         string             `json:"origin"`
	OriginServerTS jsontime.UnixMilli `json:"origin_server_ts"`
	PDUs           []PDU              `json:"pdus"`
}

func (c *Client) Backfill(ctx context.Context, req *ReqBackfill) (resp *RespBackfill, err error) {
	_, _, err = c.MakeFullRequest(ctx, RequestParams{
		ServerName: req.ServerName,
		Method:     http.MethodGet,
		Path:       URLPath{"v1", "backfill", req.RoomID},
		Query: url.Values{
			"limit": {strconv.Itoa(req.Limit)},
			"v":     exslices.CastToString[string](req.BackfillFrom),
		},
		Authenticate: true,
		ResponseJSON: &resp,
	})
	return
}

type ReqGetMissingEvents struct {
	ServerName     string       `json:"-"`
	RoomID         id.RoomID    `json:"-"`
	EarliestEvents []id.EventID `json:"earliest_events"`
	LatestEvents   []id.EventID `json:"latest_events"`
	Limit          int          `json:"limit,omitempty"`
	MinDepth       int          `json:"min_depth,omitempty"`
}

type RespGetMissingEvents struct {
	Events []PDU `json:"events"`
}

func (c *Client) GetMissingEvents(ctx context.Context, req *ReqGetMissingEvents) (resp *RespGetMissingEvents, err error) {
	err = c.MakeRequest(ctx, req.ServerName, true, http.MethodPost, URLPath{"v1", "get_missing_events", req.RoomID}, req, &resp)
	return
}

func (c *Client) GetEvent(ctx context.Context, serverName string, eventID id.EventID) (resp *RespBackfill, err error) {
	err = c.MakeRequest(ctx, serverName, true, http.MethodGet, URLPath{"v1", "event", eventID}, nil, &resp)
	return
}

type RespGetState struct {
	AuthChain []PDU `json:"auth_chain"`
	PDUs      []PDU `json:"pdus"`
}

func (c *Client) GetState(ctx context.Context, serverName string, roomID id.RoomID, eventID id.EventID) (resp *RespGetState, err error) {
	_, _, err = c.MakeFullRequest(ctx, RequestParams{
		ServerName: serverName,
		Method:     http.MethodGet,
		Path:       URLPath{"v1", "state", roomID},
		Query: url.Values{
			"event_id": {string(eventID)},
		},
		Authenticate: true,
		ResponseJSON: &resp,
	})
	return
}

type RespGetStateIDs struct {
	AuthChain []id.EventID `json:"auth_chain_ids"`
	PDUs      []id.EventID `json:"pdu_ids"`
}

func (c *Client) GetStateIDs(ctx context.Context, serverName string, roomID id.RoomID, eventID id.EventID) (resp *RespGetStateIDs, err error) {
	_, _, err = c.MakeFullRequest(ctx, RequestParams{
		ServerName: serverName,
		Method:     http.MethodGet,
		Path:       URLPath{"v1", "state_ids", roomID},
		Query: url.Values{
			"event_id": {string(eventID)},
		},
		Authenticate: true,
		ResponseJSON: &resp,
	})
	return
}

func (c *Client) TimestampToEvent(ctx context.Context, serverName string, roomID id.RoomID, timestamp time.Time, dir mautrix.Direction) (resp *mautrix.RespTimestampToEvent, err error) {
	_, _, err = c.MakeFullRequest(ctx, RequestParams{
		ServerName: serverName,
		Method:     http.MethodGet,
		Path:       URLPath{"v1", "timestamp_to_event", roomID},
		Query: url.Values{
			"dir": {string(dir)},
			"ts":  {strconv.FormatInt(timestamp.UnixMilli(), 10)},
		},
		Authenticate: true,
		ResponseJSON: &resp,
	})
	return
}

func (c *Client) QueryProfile(ctx context.Context, serverName string, userID id.UserID) (resp *mautrix.RespUserProfile, err error) {
	err = c.Query(ctx, serverName, "profile", url.Values{"user_id": {userID.String()}}, &resp)
	return
}

func (c *Client) QueryDirectory(ctx context.Context, serverName string, roomAlias id.RoomAlias) (resp *mautrix.RespAliasResolve, err error) {
	err = c.Query(ctx, serverName, "directory", url.Values{"room_alias": {roomAlias.String()}}, &resp)
	return
}

func (c *Client) Query(ctx context.Context, serverName, queryType string, queryParams url.Values, respStruct any) (err error) {
	_, _, err = c.MakeFullRequest(ctx, RequestParams{
		ServerName:   serverName,
		Method:       http.MethodGet,
		Path:         URLPath{"v1", "query", queryType},
		Query:        queryParams,
		Authenticate: true,
		ResponseJSON: respStruct,
	})
	return
}

func queryToValues(query map[string]string) url.Values {
	values := make(url.Values, len(query))
	for k, v := range query {
		values[k] = []string{v}
	}
	return values
}

func (c *Client) PublicRooms(ctx context.Context, serverName string, req *mautrix.ReqPublicRooms) (resp *mautrix.RespPublicRooms, err error) {
	_, _, err = c.MakeFullRequest(ctx, RequestParams{
		ServerName:   serverName,
		Method:       http.MethodGet,
		Path:         URLPath{"v1", "publicRooms"},
		Query:        queryToValues(req.Query()),
		Authenticate: true,
		ResponseJSON: &resp,
	})
	return
}

type RespOpenIDUserInfo struct {
	Sub id.UserID `json:"sub"`
}

func (c *Client) GetOpenIDUserInfo(ctx context.Context, serverName, accessToken string) (resp *RespOpenIDUserInfo, err error) {
	_, _, err = c.MakeFullRequest(ctx, RequestParams{
		ServerName:   serverName,
		Method:       http.MethodGet,
		Path:         URLPath{"v1", "openid", "userinfo"},
		Query:        url.Values{"access_token": {accessToken}},
		ResponseJSON: &resp,
	})
	return
}

type URLPath []any

func (fup URLPath) FullPath() []any {
	return append([]any{"_matrix", "federation"}, []any(fup)...)
}

type KeyURLPath []any

func (fkup KeyURLPath) FullPath() []any {
	return append([]any{"_matrix", "key"}, []any(fkup)...)
}

type RequestParams struct {
	ServerName   string
	Method       string
	Path         mautrix.PrefixableURLPath
	Query        url.Values
	Authenticate bool
	RequestJSON  any

	ResponseJSON any
	DontReadBody bool
}

func (c *Client) MakeRequest(ctx context.Context, serverName string, authenticate bool, method string, path mautrix.PrefixableURLPath, reqJSON, respJSON any) error {
	_, _, err := c.MakeFullRequest(ctx, RequestParams{
		ServerName:   serverName,
		Method:       method,
		Path:         path,
		Authenticate: authenticate,
		RequestJSON:  reqJSON,
		ResponseJSON: respJSON,
	})
	return err
}

func (c *Client) MakeFullRequest(ctx context.Context, params RequestParams) ([]byte, *http.Response, error) {
	req, err := c.compileRequest(ctx, params)
	if err != nil {
		return nil, nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, mautrix.HTTPError{
			Request:  req,
			Response: resp,

			Message:      "request error",
			WrappedError: err,
		}
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	var body []byte
	if resp.StatusCode >= 400 {
		body, err = mautrix.ParseErrorResponse(req, resp)
		return body, resp, err
	} else if params.ResponseJSON != nil || !params.DontReadBody {
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return body, resp, mautrix.HTTPError{
				Request:  req,
				Response: resp,

				Message:      "failed to read response body",
				WrappedError: err,
			}
		}
		if params.ResponseJSON != nil {
			err = json.Unmarshal(body, params.ResponseJSON)
			if err != nil {
				return body, resp, mautrix.HTTPError{
					Request:  req,
					Response: resp,

					Message:      "failed to unmarshal response JSON",
					ResponseBody: string(body),
					WrappedError: err,
				}
			}
		}
	}
	return body, resp, nil
}

func (c *Client) compileRequest(ctx context.Context, params RequestParams) (*http.Request, error) {
	reqURL := mautrix.BuildURL(&url.URL{
		Scheme: "matrix-federation",
		Host:   params.ServerName,
	}, params.Path.FullPath()...)
	reqURL.RawQuery = params.Query.Encode()
	var reqJSON json.RawMessage
	var reqBody io.Reader
	if params.RequestJSON != nil {
		var err error
		reqJSON, err = json.Marshal(params.RequestJSON)
		if err != nil {
			return nil, mautrix.HTTPError{
				Message:      "failed to marshal JSON",
				WrappedError: err,
			}
		}
		reqBody = bytes.NewReader(reqJSON)
	}
	req, err := http.NewRequestWithContext(ctx, params.Method, reqURL.String(), reqBody)
	if err != nil {
		return nil, mautrix.HTTPError{
			Message:      "failed to create request",
			WrappedError: err,
		}
	}
	req.Header.Set("User-Agent", c.UserAgent)
	if params.Authenticate {
		if c.ServerName == "" || c.Key == nil {
			return nil, mautrix.HTTPError{
				Message: "client not configured for authentication",
			}
		}
		auth, err := (&signableRequest{
			Method:      req.Method,
			URI:         reqURL.RequestURI(),
			Origin:      c.ServerName,
			Destination: params.ServerName,
			Content:     reqJSON,
		}).Sign(c.Key)
		if err != nil {
			return nil, mautrix.HTTPError{
				Message:      "failed to sign request",
				WrappedError: err,
			}
		}
		req.Header.Set("Authorization", auth)
	}
	return req, nil
}

type signableRequest struct {
	Method      string          `json:"method"`
	URI         string          `json:"uri"`
	Origin      string          `json:"origin"`
	Destination string          `json:"destination"`
	Content     json.RawMessage `json:"content,omitempty"`
}

func (r *signableRequest) Verify(key id.SigningKey, sig string) error {
	message, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}
	return VerifyJSONRaw(key, sig, message)
}

func (r *signableRequest) Sign(key *SigningKey) (string, error) {
	sig, err := key.SignJSON(r)
	if err != nil {
		return "", err
	}
	return XMatrixAuth{
		Origin:      r.Origin,
		Destination: r.Destination,
		KeyID:       key.ID,
		Signature:   sig,
	}.String(), nil
}
