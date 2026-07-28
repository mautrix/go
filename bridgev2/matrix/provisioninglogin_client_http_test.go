package matrix

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"maunium.net/go/mautrix/bridgev2"
)

type clientHTTPTestLogin struct {
	response *bridgev2.LoginClientHTTPResponse
	next     *bridgev2.LoginStep
}

func (login *clientHTTPTestLogin) Start(context.Context) (*bridgev2.LoginStep, error) {
	return nil, nil
}

func (login *clientHTTPTestLogin) Cancel() {}

func (login *clientHTTPTestLogin) SubmitClientHTTPResponse(
	_ context.Context,
	response *bridgev2.LoginClientHTTPResponse,
) (*bridgev2.LoginStep, error) {
	login.response = response
	return login.next, nil
}

func TestPostLoginStepClientHTTP(t *testing.T) {
	process := &clientHTTPTestLogin{
		next: &bridgev2.LoginStep{
			Type:         bridgev2.LoginStepTypeUserInput,
			StepID:       "next",
			Instructions: "Next",
			UserInputParams: &bridgev2.LoginUserInputParams{
				Fields: []bridgev2.LoginInputDataField{},
			},
		},
	}
	login := &ProvLogin{
		ID:      "process",
		Process: process,
		NextStep: &bridgev2.LoginStep{
			Type:             bridgev2.LoginStepTypeClientHTTP,
			StepID:           "http-step",
			ClientHTTPParams: &bridgev2.LoginClientHTTPParams{RequestID: "request-1"},
		},
		Ctx: context.Background(),
	}
	prov := &ProvisioningAPI{
		logins: map[string]*ProvLogin{"process": login},
	}
	request := httptest.NewRequest(http.MethodPost, "/unused", bytes.NewBufferString(`{
		"request_id": "request-1",
		"status_code": 200,
		"final_url": "https://example.com/home",
		"headers": {
			"Set-Cookie": ["first=1; Path=/", "second=2; Path=/"]
		},
		"body": "b2s="
	}`))
	request.SetPathValue("loginProcessID", "process")
	request.SetPathValue("stepID", "http-step")
	request.SetPathValue("stepType", "client_http")
	response := httptest.NewRecorder()

	prov.PostLoginStep(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	require.NotNil(t, process.response)
	require.Equal(t, "request-1", process.response.RequestID)
	require.Equal(t, http.StatusOK, process.response.StatusCode)
	require.Equal(t, []byte("ok"), process.response.Body)
	require.Equal(t, []string{"first=1; Path=/", "second=2; Path=/"}, process.response.Headers.Values("Set-Cookie"))
	require.Equal(t, process.next, login.NextStep)
}

func TestPostLoginStepClientHTTPRejectsMalformedResponse(t *testing.T) {
	prov := &ProvisioningAPI{
		logins: map[string]*ProvLogin{
			"process": {
				ID:      "process",
				Process: &clientHTTPTestLogin{},
				NextStep: &bridgev2.LoginStep{
					Type:   bridgev2.LoginStepTypeClientHTTP,
					StepID: "http-step",
				},
				Ctx: context.Background(),
			},
		},
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/unused",
		bytes.NewBufferString(`{"request_id":"request-1","status_code":"not-a-number"}`),
	)
	request.SetPathValue("loginProcessID", "process")
	request.SetPathValue("stepID", "http-step")
	request.SetPathValue("stepType", "client_http")
	response := httptest.NewRecorder()

	prov.PostLoginStep(response, request)

	require.Equal(t, http.StatusBadRequest, response.Code)
}

func TestPostLoginStepClientHTTPRejectsInvalidResponse(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing request ID",
			body: `{"status_code":200}`,
		},
		{
			name: "mismatched request ID",
			body: `{"request_id":"other-request","status_code":200}`,
		},
		{
			name: "missing status and error",
			body: `{"request_id":"request-1"}`,
		},
		{
			name: "status and error both present",
			body: `{"request_id":"request-1","status_code":500,"error":"request failed"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			process := &clientHTTPTestLogin{}
			prov := &ProvisioningAPI{
				logins: map[string]*ProvLogin{
					"process": {
						ID:      "process",
						Process: process,
						NextStep: &bridgev2.LoginStep{
							Type:   bridgev2.LoginStepTypeClientHTTP,
							StepID: "http-step",
							ClientHTTPParams: &bridgev2.LoginClientHTTPParams{
								RequestID: "request-1",
							},
						},
						Ctx: context.Background(),
					},
				},
			}
			request := httptest.NewRequest(http.MethodPost, "/unused", bytes.NewBufferString(test.body))
			request.SetPathValue("loginProcessID", "process")
			request.SetPathValue("stepID", "http-step")
			request.SetPathValue("stepType", "client_http")
			response := httptest.NewRecorder()

			prov.PostLoginStep(response, request)

			require.Equal(t, http.StatusBadRequest, response.Code)
			require.Nil(t, process.response)
		})
	}
}
