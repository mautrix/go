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
	Session     *Session
}

// NewPlainRequest creates a new payloadless Matrix API request.
func (s *Session) NewPlainRequest(url string, urlArgs ...interface{}) Request {
	return Request{Session: s, URL: s.GetURL(url, urlArgs...)}
}

// NewRequest creates a new Matrix API request with a custom payload.
func (s *Session) NewRequest(payload, contentType, url string, urlArgs ...interface{}) Request {
	return Request{Session: s, Payload: payload, ContentType: contentType, URL: s.GetURL(url, urlArgs...)}
}

// NewJSONRequest creates a new Matrix API request and marshals the given object to JSON and uses it as the payload.
func (s *Session) NewJSONRequest(payload interface{}, url string, urlArgs ...interface{}) Request {
	payloadData, _ := json.Marshal(payload)
	return s.NewRequest(string(payloadData), "application/json", url, urlArgs...)
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
