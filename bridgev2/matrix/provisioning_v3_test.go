// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mau.fi/util/l10n"

	"maunium.net/go/mautrix/bridgev2"
)

var (
	testL10N           = l10n.NewNamespace("provisioning-test")
	testMsgFlowName    = testL10N.Define("flow.password.name", "Password")
	testMsgFlowDesc    = testL10N.Define("flow.password.description", "Log in with your username and password")
	testMsgInstruction = testL10N.Define("step.password.instructions", "Enter the credentials for {service}")
	testMsgUsername    = testL10N.Define("field.username.name", "Username")
	testMsgUsernameEx  = testL10N.Define("field.username.placeholder", "alice")
	testMsgMethod      = testL10N.Define("field.method.name", "Verification method")
	testMsgMethodSMS   = testL10N.Define("field.method.option.sms", "Text message")
	testMsgComplete    = testL10N.Define("step.complete.instructions", "Successfully logged in as {name}")
)

func testLoginFlows() []bridgev2.LoginFlow {
	return []bridgev2.LoginFlow{{
		ID:          "password",
		Name:        testMsgFlowName.Message(),
		Description: testMsgFlowDesc.Message(),
	}, {
		ID:          "legacy",
		Name:        l10n.Unlocalized("Legacy"),
		Description: l10n.Unlocalized("A flow that hasn't been converted yet"),
	}}
}

func testLoginSteps() map[string]*bridgev2.LoginStep {
	return map[string]*bridgev2.LoginStep{
		"user_input": {
			Type:         bridgev2.LoginStepTypeUserInput,
			StepID:       "fi.mau.test.password",
			Instructions: testMsgInstruction.Render(l10n.Params{"service": "Example"}),
			UserInputParams: &bridgev2.LoginUserInputParams{
				Fields: []bridgev2.LoginInputDataField{{
					Type:        bridgev2.LoginInputFieldTypeUsername,
					ID:          "username",
					Name:        testMsgUsername.Message(),
					Placeholder: testMsgUsernameEx.Message(),
				}, {
					Type: bridgev2.LoginInputFieldTypeSelect,
					ID:   "method",
					Name: testMsgMethod.Message(),
					Options: append(
						[]bridgev2.LoginInputOption{{Value: "sms", Label: testMsgMethodSMS.Message()}},
						bridgev2.UnlocalizedOptions("Authenticator app")...,
					),
				}},
				CanCancel: true,
			},
		},
		"display_and_wait": {
			Type:         bridgev2.LoginStepTypeDisplayAndWait,
			StepID:       "fi.mau.test.qr",
			Instructions: l10n.Unlocalized("Scan the QR code"),
			DisplayAndWaitParams: &bridgev2.LoginDisplayAndWaitParams{
				Type: bridgev2.LoginDisplayTypeQR,
				Data: "qr-data",
			},
		},
		"complete": {
			Type:         bridgev2.LoginStepTypeComplete,
			StepID:       "fi.mau.test.complete",
			Instructions: testMsgComplete.Render(l10n.Params{"name": "+15550100"}),
			CompleteParams: &bridgev2.LoginCompleteParams{
				UserLoginID: "15550100",
			},
		},
	}
}

func serveVersioned(t *testing.T, version string, handler http.HandlerFunc) []byte {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v3/test", handler)
	mux.HandleFunc("GET /v4/test", handler)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/"+version+"/test", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var indented bytes.Buffer
	require.NoError(t, json.Indent(&indented, rec.Body.Bytes(), "", "\t"))
	indented.WriteByte('\n')
	return indented.Bytes()
}

// checkGolden compares output to testdata/provisioning/<name>.json. The v3
// files pin the legacy wire format, which must not change. Run with
// UPDATE_GOLDEN=1 to rewrite them.
func checkGolden(t *testing.T, name string, output []byte) {
	t.Helper()
	path := filepath.Join("testdata", "provisioning", name+".json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, output, 0o644))
		return
	}
	expected, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(expected), string(output))
}

func TestProvisioningLoginGolden(t *testing.T) {
	for _, version := range []string{"v3", "v4"} {
		checkGolden(t, version+"_login_flows", serveVersioned(t, version, func(w http.ResponseWriter, r *http.Request) {
			writeLoginFlows(w, r, testLoginFlows())
		}))
		for name, step := range testLoginSteps() {
			checkGolden(t, version+"_login_step_"+name, serveVersioned(t, version, func(w http.ResponseWriter, r *http.Request) {
				writeLoginStep(w, r, "login-id", step)
			}))
		}
	}
}

func TestProvisioningWhoamiV3(t *testing.T) {
	resp := &RespWhoami{Network: bridgev2.BridgeName{DisplayName: "Test"}, LoginFlows: testLoginFlows(), Logins: []RespWhoamiLogin{}}
	data, err := json.Marshal(&v3RespWhoami{RespWhoami: resp, LoginFlows: toV3LoginFlows(resp.LoginFlows).Flows})
	require.NoError(t, err)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(data, &raw))
	flows := raw["login_flows"].([]any)
	require.Len(t, flows, 2)
	assert.Equal(t, "Password", flows[0].(map[string]any)["name"])
	assert.Contains(t, raw, "network")
}

// Clients that support v4 read v3 responses from older bridges with the same
// types. Localizable strings become unlocalized and option labels equal values.
func TestProvisioningV3ParsesIntoV4Types(t *testing.T) {
	step := testLoginSteps()["user_input"]
	body := serveVersioned(t, "v3", func(w http.ResponseWriter, r *http.Request) {
		writeLoginStep(w, r, "login-id", step)
	})
	var parsed RespSubmitLogin
	require.NoError(t, json.Unmarshal(body, &parsed))
	assert.Equal(t, l10n.Unlocalized("Enter the credentials for Example"), parsed.Instructions)
	fields := parsed.UserInputParams.Fields
	assert.Equal(t, l10n.Unlocalized("Username"), fields[0].Name)
	assert.Equal(t, l10n.Unlocalized("alice"), fields[0].Placeholder)
	assert.Equal(t, bridgev2.UnlocalizedOptions("sms", "Authenticator app"), fields[1].Options)
	assert.True(t, parsed.UserInputParams.CanCancel)

	body = serveVersioned(t, "v4", func(w http.ResponseWriter, r *http.Request) {
		writeLoginStep(w, r, "login-id", step)
	})
	parsed = RespSubmitLogin{}
	require.NoError(t, json.Unmarshal(body, &parsed))
	assert.Equal(t, step.Instructions, parsed.Instructions)
	assert.Equal(t, step.UserInputParams.Fields[1].Options, parsed.UserInputParams.Fields[1].Options)
}
