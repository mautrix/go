package bridgev2

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoginClientHTTPJSONRoundTrip(t *testing.T) {
	step := LoginStep{
		Type:         LoginStepTypeClientHTTP,
		StepID:       "com.example.client_http",
		Instructions: "Sending login request",
		ClientHTTPParams: &LoginClientHTTPParams{
			RequestID: "request-1",
			Method:    http.MethodPost,
			URL:       "https://example.com/login",
			Headers: http.Header{
				"Accept":       {"application/json"},
				"X-Multi-Test": {"one", "two"},
			},
			Body: []byte{0, 1, 2, 3},
		},
	}

	data, err := json.Marshal(&step)
	require.NoError(t, err)
	require.JSONEq(t, `{
		"type": "client_http",
		"step_id": "com.example.client_http",
		"instructions": "Sending login request",
		"client_http": {
			"request_id": "request-1",
			"method": "POST",
			"url": "https://example.com/login",
			"headers": {
				"Accept": ["application/json"],
				"X-Multi-Test": ["one", "two"]
			},
			"body": "AAECAw=="
		}
	}`, string(data))

	var decoded LoginStep
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Equal(t, step, decoded)
}

func TestLoginClientHTTPResponseJSONRoundTrip(t *testing.T) {
	response := LoginClientHTTPResponse{
		RequestID:  "request-1",
		StatusCode: http.StatusOK,
		FinalURL:   "https://example.com/home",
		Headers: http.Header{
			"Content-Type": {"application/json"},
			"Set-Cookie":   {"first=1; Path=/", "second=2; Path=/"},
		},
		Body: []byte(`{"ok":true}`),
	}

	data, err := json.Marshal(&response)
	require.NoError(t, err)

	var decoded LoginClientHTTPResponse
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Equal(t, response, decoded)
}
