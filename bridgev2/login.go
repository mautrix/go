// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"

	"maunium.net/go/mautrix/bridgev2/networkid"
)

type LoginProcess interface {
	Start(ctx context.Context) (*LoginStep, error)
	Cancel()
}

type LoginProcessDisplayAndWait interface {
	LoginProcess
	Wait(ctx context.Context) (*LoginStep, error)
}

type LoginProcessUserInput interface {
	LoginProcess
	SubmitUserInput(ctx context.Context, input map[string]string) (*LoginStep, error)
}

type LoginProcessCookies interface {
	LoginProcess
	SubmitCookies(ctx context.Context, cookies map[string]string) (*LoginStep, error)
}

type LoginFlow struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	ID          string `json:"id"`
}

type LoginStepType string

const (
	LoginStepTypeUserInput      LoginStepType = "user_input"
	LoginStepTypeCookies        LoginStepType = "cookies"
	LoginStepTypeDisplayAndWait LoginStepType = "display_and_wait"
	LoginStepTypeComplete       LoginStepType = "complete"
)

type LoginDisplayType string

const (
	LoginDisplayTypeQR    LoginDisplayType = "qr"
	LoginDisplayTypeEmoji LoginDisplayType = "emoji"
	LoginDisplayTypeCode  LoginDisplayType = "code"
)

type LoginStep struct {
	// The type of login step
	Type LoginStepType `json:"type"`
	// A unique ID for this step. The ID should be same for every login using the same flow,
	// but it should be different for different bridges and step types.
	//
	// For example, Telegram's QR scan followed by a 2-factor password
	// might use the IDs `fi.mau.telegram.qr` and `fi.mau.telegram.2fa_password`.
	StepID string `json:"step_id"`
	// Instructions contains human-readable instructions for completing the login step.
	Instructions string `json:"instructions"`

	// Exactly one of the following structs must be filled depending on the step type.

	DisplayAndWaitParams *LoginDisplayAndWaitParams `json:"display_and_wait"`
	CookiesParams        *LoginCookiesParams        `json:"cookies"`
	UserInputParams      *LoginUserInputParams      `json:"user_input"`
	CompleteParams       *LoginCompleteParams       `json:"complete"`
}

type LoginDisplayAndWaitParams struct {
	// The type of thing to display (QR, emoji or text code)
	Type LoginDisplayType `json:"type"`
	// The thing to display (raw data for QR, unicode emoji for emoji, plain string for code)
	Data string `json:"data"`
	// An image containing the thing to display. If present, this is recommended over using data directly.
	// For emojis, the URL to the canonical image representation of the emoji
	ImageURL string `json:"image_url,omitempty"`
}

type LoginCookiesParams struct {
	URL string `json:"url"`

	CookieDomain     string   `json:"cookie_domain,omitempty"`
	CookieKeys       []string `json:"cookie_keys,omitempty"`
	LocalStorageKeys []string `json:"local_storage_keys,omitempty"`
	SpecialKeys      []string `json:"special_keys,omitempty"`
}

type LoginInputFieldType string

const (
	LoginInputFieldTypeUsername    LoginInputFieldType = "username"
	LoginInputFieldTypePassword    LoginInputFieldType = "password"
	LoginInputFieldTypePhoneNumber LoginInputFieldType = "phone_number"
	LoginInputFieldTypeEmail       LoginInputFieldType = "email"
	LoginInputFieldType2FACode     LoginInputFieldType = "2fa_code"
)

type LoginInputDataField struct {
	// The type of input field as a hint for the client.
	Type LoginInputFieldType `json:"type"`
	// The ID of the field to be used as the key in the map that is submitted to the connector.
	ID string `json:"id"`
	// The name of the field shown to the user.
	Name string `json:"name"`
	// The description of the field shown to the user.
	Description string `json:"description"`
	// A regex pattern that the client can use to validate input client-side.
	Pattern string `json:"pattern,omitempty"`
	// A function that validates the input and optionally cleans it up before it's submitted to the connector.
	Validate func(string) (string, error) `json:"-"`
}

type LoginUserInputParams struct {
	// The fields that the user needs to fill in.
	Fields []LoginInputDataField `json:"fields"`
}

type LoginCompleteParams struct {
	UserLoginID networkid.UserLoginID `json:"user_login_id"`
}

type LoginSubmit struct {
}
