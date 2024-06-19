// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"fmt"
	"strings"

	"maunium.net/go/mautrix/bridgev2/networkid"
)

// LoginProcess represents a single occurrence of a user logging into the remote network.
type LoginProcess interface {
	// Start starts the process and returns the first step.
	//
	// For example, a network using QR login may connect to the network, fetch a QR code,
	// and return a DisplayAndWait-type step.
	//
	// This will only ever be called once.
	Start(ctx context.Context) (*LoginStep, error)
	// Cancel stops the login process and cleans up any resources.
	// No other methods will be called after cancel.
	//
	// Cancel will not be called if any other method returned an error:
	// errors are always treated as fatal and the process is assumed to be automatically cancelled.
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
	URL       string `json:"url"`
	UserAgent string `json:"user_agent,omitempty"`

	CookieDomain     string   `json:"cookie_domain,omitempty"`
	CookieKeys       []string `json:"cookie_keys,omitempty"`
	LocalStorageKeys []string `json:"local_storage_keys,omitempty"`
	SpecialKeys      []string `json:"special_keys,omitempty"`
	SpecialExtractJS string   `json:"special_extract_js,omitempty"`
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

var numberCleaner = strings.NewReplacer("-", "", " ", "", "(", "", ")", "")

func isOnlyNumbers(input string) bool {
	for _, r := range input {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func CleanPhoneNumber(phone string) (string, error) {
	phone = numberCleaner.Replace(phone)
	if len(phone) < 2 {
		return "", fmt.Errorf("phone number must start with + and contain numbers")
	} else if phone[0] != '+' {
		return "", fmt.Errorf("phone number must start with +")
	} else if !isOnlyNumbers(phone[1:]) {
		return "", fmt.Errorf("phone number must only contain numbers")
	}
	return phone, nil
}

func (f *LoginInputDataField) FillDefaultValidate() {
	noopValidate := func(input string) (string, error) { return input, nil }
	if f.Validate != nil {
		return
	}
	switch f.Type {
	case LoginInputFieldTypePhoneNumber:
		f.Validate = CleanPhoneNumber
	case LoginInputFieldTypeEmail:
		f.Validate = func(email string) (string, error) {
			if !strings.ContainsRune(email, '@') {
				return "", fmt.Errorf("invalid email")
			}
			return email, nil
		}
	default:
		f.Validate = noopValidate
	}
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
