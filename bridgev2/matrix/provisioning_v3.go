// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"net/http"
	"strings"

	"go.mau.fi/util/exhttp"

	"maunium.net/go/mautrix/bridgev2"
)

// v3 sends localizable fields as plain strings and select options as values.
// These types shadow only those fields so other fields stay in sync with v4.

func isV3Request(r *http.Request) bool {
	return strings.Contains(r.Pattern, " /v3/")
}

type v3LoginFlow struct {
	bridgev2.LoginFlow
	Name        string `json:"name"`
	Description string `json:"description"`
}

type v3RespLoginFlows struct {
	Flows []v3LoginFlow `json:"flows"`
}

type v3RespWhoami struct {
	*RespWhoami
	LoginFlows []v3LoginFlow `json:"login_flows"`
}

type v3LoginStep struct {
	*bridgev2.LoginStep
	Instructions    string                  `json:"instructions"`
	UserInputParams *v3LoginUserInputParams `json:"user_input,omitzero"`
}

type v3RespSubmitLogin struct {
	LoginID string `json:"login_id"`
	*v3LoginStep
}

type v3LoginUserInputParams struct {
	*bridgev2.LoginUserInputParams
	Fields []v3LoginInputDataField `json:"fields"`
}

type v3LoginInputDataField struct {
	*bridgev2.LoginInputDataField
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Placeholder string   `json:"placeholder,omitempty"`
	Options     []string `json:"options,omitempty"`
}

func toV3LoginFlows(flows []bridgev2.LoginFlow) *v3RespLoginFlows {
	out := make([]v3LoginFlow, len(flows))
	for i, flow := range flows {
		out[i] = v3LoginFlow{
			LoginFlow:   flow,
			Name:        flow.Name.Text,
			Description: flow.Description.Text,
		}
	}
	return &v3RespLoginFlows{Flows: out}
}

func toV3LoginStep(step *bridgev2.LoginStep) *v3LoginStep {
	if step == nil {
		return nil
	}
	out := &v3LoginStep{
		LoginStep:    step,
		Instructions: step.Instructions.Text,
	}
	if step.UserInputParams != nil {
		fields := make([]v3LoginInputDataField, len(step.UserInputParams.Fields))
		for i := range step.UserInputParams.Fields {
			field := &step.UserInputParams.Fields[i]
			var options []string
			if field.Options != nil {
				options = make([]string, len(field.Options))
				for j, opt := range field.Options {
					options[j] = opt.Value
				}
			}
			fields[i] = v3LoginInputDataField{
				LoginInputDataField: field,
				Name:                field.Name.Text,
				Description:         field.Description.Text,
				Placeholder:         field.Placeholder.Text,
				Options:             options,
			}
		}
		out.UserInputParams = &v3LoginUserInputParams{
			LoginUserInputParams: step.UserInputParams,
			Fields:               fields,
		}
	}
	return out
}

func writeLoginFlows(w http.ResponseWriter, r *http.Request, flows []bridgev2.LoginFlow) {
	if isV3Request(r) {
		exhttp.WriteJSONResponse(w, http.StatusOK, toV3LoginFlows(flows))
	} else {
		exhttp.WriteJSONResponse(w, http.StatusOK, &RespLoginFlows{Flows: flows})
	}
}

func writeLoginStep(w http.ResponseWriter, r *http.Request, loginID string, step *bridgev2.LoginStep) {
	if isV3Request(r) {
		exhttp.WriteJSONResponse(w, http.StatusOK, &v3RespSubmitLogin{LoginID: loginID, v3LoginStep: toV3LoginStep(step)})
	} else {
		exhttp.WriteJSONResponse(w, http.StatusOK, &RespSubmitLogin{LoginID: loginID, LoginStep: step})
	}
}
