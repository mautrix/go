// mautrix - A Matrix client-server library intended for bots.
// Copyright (C) 2017 Tulir Asokan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package mautrix

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

// Request wraps a Matrix API request.
type Request struct {
	URL         string
	Payload     string
	ContentType string
	Session     *MatrixBot
}

// NewPlainRequest creates a new payloadless Matrix API request.
func (mx *MatrixBot) NewPlainRequest(url string, urlArgs ...interface{}) Request {
	return Request{Session: mx, URL: mx.GetURL(url, urlArgs...)}
}

// NewRequest creates a new Matrix API request with a custom payload.
func (mx *MatrixBot) NewRequest(payload, contentType, url string, urlArgs ...interface{}) Request {
	return Request{Session: mx, Payload: payload, ContentType: contentType, URL: mx.GetURL(url, urlArgs...)}
}

// NewJSONRequest creates a new Matrix API request and marshals the given object to JSON and uses it as the payload.
func (mx *MatrixBot) NewJSONRequest(payload interface{}, url string, urlArgs ...interface{}) Request {
	payloadData, _ := json.Marshal(payload)
	return mx.NewRequest(string(payloadData), "application/json", url, urlArgs...)
}

// CompletedRequest is a Matrix API request that has been called.
type CompletedRequest struct {
	Source   Request
	Response *http.Response
	Method   string
	Error    error
}

// GET executes this request with HTTP GET.
func (req Request) GET() CompletedRequest {
	return req.HTTP(http.MethodGet)
}

// PUT executes this request with HTTP PUT.
func (req Request) PUT() CompletedRequest {
	return req.HTTP(http.MethodPut)
}

// POST executes this request with HTTP POST.
func (req Request) POST() CompletedRequest {
	return req.HTTP(http.MethodPost)
}

// HTTP executes this request with the given HTTP method.
func (req Request) HTTP(method string) CompletedRequest {
	var payloadReader io.Reader
	if len(req.Payload) > 0 {
		payloadReader = strings.NewReader(req.Payload)
	}

	httpReq, err := http.NewRequest(method, req.URL, payloadReader)
	if err != nil {
		return CompletedRequest{Source: req, Method: method, Response: nil, Error: err}
	}

	if len(req.ContentType) > 0 {
		httpReq.Header.Set("Content-Type", req.ContentType)
	}

	resp, err := http.DefaultClient.Do(httpReq)
	return CompletedRequest{Source: req, Method: method, Response: resp, Error: err}
}

// OK checks if the request completed successfully.
func (creq CompletedRequest) OK() bool {
	if creq.Response == nil || creq.Error != nil {
		creq.Close()
		return false
	}
	return true
}

// CheckStatusOK makes sure that the response HTTP status code is OK 200.
func (creq CompletedRequest) CheckStatusOK() bool {
	return creq.CheckStatus(http.StatusOK)
}

// CheckStatus makes sure that the response HTTP status code is correct.
func (creq CompletedRequest) CheckStatus(expected int) bool {
	return creq.Response.StatusCode == expected
}

// JSON reads the body of the response and parses it from JSON into an interface.
func (creq CompletedRequest) JSON(decodeInto interface{}) error {
	defer creq.Close()
	return json.NewDecoder(creq.Response.Body).Decode(&decodeInto)
}

// Text reads the body of the response and returns it as a string.
func (creq CompletedRequest) Text() (string, error) {
	defer creq.Close()
	data, err := ioutil.ReadAll(creq.Response.Body)
	return string(data), err
}

// Close closes the response body stream.
func (creq CompletedRequest) Close() {
	if creq.Response != nil {
		creq.Response.Body.Close()
	}
}
