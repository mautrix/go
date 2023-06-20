package mautrix

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/tidwall/gjson"
)

func TestBackoffFromResponse(t *testing.T) {
	now := time.Now().Truncate(time.Second)

	defaultBackoff := time.Duration(123)

	for name, tt := range map[string]struct {
		headerValue string
		expected    time.Duration
		expectedLog string
	}{
		"AsDate": {
			headerValue: now.In(time.UTC).Add(5 * time.Hour).Format(http.TimeFormat),
			expected:    time.Duration(5) * time.Hour,
			expectedLog: "",
		},
		"AsSeconds": {
			headerValue: "12345",
			expected:    time.Duration(12345) * time.Second,
			expectedLog: "",
		},
		"Missing": {
			headerValue: "",
			expected:    defaultBackoff,
			expectedLog: "",
		},
		"Bad": {
			headerValue: "invalid",
			expected:    defaultBackoff,
			expectedLog: `Failed to parse Retry-After header value`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			c := &Client{Log: zerolog.New(&out)}

			actual := parseBackoffFromResponse(
				(&http.Request{}).WithContext(c.Log.WithContext(context.Background())),
				&http.Response{
					Header: http.Header{
						"Retry-After": []string{tt.headerValue},
					},
				},
				now,
				time.Duration(123),
			)

			if actual != tt.expected {
				t.Fatalf("Backoff duration output mismatch, expected %s, got %s", tt.expected, actual)
			}

			lastLogged := gjson.GetBytes(out.Bytes(), zerolog.MessageFieldName).Str
			if lastLogged != tt.expectedLog {
				t.Fatalf(`Log line mismatch, expected "%s", got "%s"`, tt.expectedLog, lastLogged)
			}
		})
	}
}
