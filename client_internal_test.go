package mautrix

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

type testLogger struct {
	StubLogger

	lastLogged string
}

func (tl *testLogger) Warnfln(message string, args ...interface{}) {
	tl.lastLogged = fmt.Sprintf(message, args...)
}

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
			expectedLog: `Failed to parse Retry-After header value "invalid"`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			logger := &testLogger{}

			c := &Client{Logger: logger}

			actual := c.parseBackoffFromResponse(
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

			if logger.lastLogged != tt.expectedLog {
				t.Fatalf(`Log line mismatch, expected "%s", got "%s"`, tt.expectedLog, logger.lastLogged)
			}
		})
	}
}
