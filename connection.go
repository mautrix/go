package mautrix

import (
	"io"
	"net/http"
	"strings"
)

// JSONPOST makes a JSON POST request to the given URL with the given body.
func JSONPOST(url, payload string) (*http.Response, error) {
	var payloadReader io.Reader
	if len(payload) > 0 {
		payloadReader = strings.NewReader(payload)
	}
	req, _ := http.NewRequest(http.MethodPost, url, payloadReader)
	if payloadReader != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return http.DefaultClient.Do(req)
}

// POST makes a POST request to the given URL.
func POST(url string) (*http.Response, error) {
	return JSONPOST(url, "")
}
