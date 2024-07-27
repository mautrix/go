package appservice

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

const WebsocketCommandHTTPProxy = "http_proxy"

type HTTPProxyRequest struct {
	Method  string          `json:"method"`
	Path    string          `json:"path"`
	Query   string          `json:"query"`
	Headers http.Header     `json:"headers"`
	Body    json.RawMessage `json:"body"`
}

type HTTPProxyResponse struct {
	Status  int             `json:"status"`
	Headers http.Header     `json:"headers"`
	Body    json.RawMessage `json:"body"`

	bodyBuf bytes.Buffer
}

func (p *HTTPProxyResponse) Header() http.Header {
	return p.Headers
}

func (p *HTTPProxyResponse) Write(bytes []byte) (int, error) {
	if p.Status == 0 {
		p.Status = http.StatusOK
	}
	return p.bodyBuf.Write(bytes)
}

func (p *HTTPProxyResponse) WriteHeader(statusCode int) {
	p.Status = statusCode
}

func (as *AppService) WebsocketHTTPProxy(cmd WebsocketCommand) (bool, interface{}) {
	var req HTTPProxyRequest
	if err := json.Unmarshal(cmd.Data, &req); err != nil {
		return false, fmt.Errorf("failed to parse proxy request: %w", err)
	}
	if cmd.Ctx == nil {
		cmd.Ctx = context.Background()
	}
	reqURL := (&url.URL{
		Scheme:   "http",
		Host:     "localhost",
		Path:     req.Path,
		RawQuery: req.Query,
	}).String()
	httpReq, err := http.NewRequestWithContext(cmd.Ctx, req.Method, reqURL, bytes.NewReader(req.Body))
	if err != nil {
		return false, fmt.Errorf("failed to create fake HTTP request: %w", err)
	}
	httpReq.RequestURI = req.Path
	if req.Query != "" {
		httpReq.RequestURI += "?" + req.Query
	}
	httpReq.RemoteAddr = "websocket"
	httpReq.Header = req.Headers

	var resp HTTPProxyResponse
	resp.Headers = make(http.Header)

	as.Router.ServeHTTP(&resp, httpReq)

	if resp.bodyBuf.Len() > 0 {
		bodyData := resp.bodyBuf.Bytes()
		if json.Valid(bodyData) {
			resp.Body = bodyData
		} else {
			resp.Body = make([]byte, 2+base64.RawStdEncoding.EncodedLen(len(bodyData)))
			resp.Body[0] = '"'
			base64.RawStdEncoding.Encode(resp.Body[1:], bodyData)
			resp.Body[len(resp.Body)-1] = '"'
		}
	}
	return true, &resp
}
