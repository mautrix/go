package mautrix

import (
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"
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

const nonceAC = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789"
const (
	letterIdxBits = 6
	letterIdxMask = 1<<letterIdxBits - 1
	letterIdxMax  = 63 / letterIdxBits
)

var src = rand.NewSource(time.Now().UnixNano())

// GenerateNonce generates a random string
func GenerateNonce() string {
	b := make([]byte, 32)
	for i, cache, remain := len(b)-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(nonceAC) {
			b[i] = nonceAC[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}
