// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/rs/zerolog"

	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"
)

// ErrLoginStepCancelled is used as the cancellation cause when the user goes
// back from a cancellable login step. It does not mean that the whole login
// process was cancelled.
var ErrLoginStepCancelled = RespError{
	ErrCode:    "FI.MAU.LOGIN_STEP_CANCELLED",
	Err:        "Login step was cancelled",
	StatusCode: http.StatusConflict,
}

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
	// Errors from other methods are always treated as fatal, but Cancel may still be called afterward.
	Cancel()
}

type LoginProcessWithOverride interface {
	LoginProcess
	// StartWithOverride starts the process with the intent of re-authenticating an existing login.
	//
	// The call to this is mutually exclusive with the call to the default Start method.
	//
	// The user login being overridden will still be logged out automatically
	// in case the complete step returns a different login.
	StartWithOverride(ctx context.Context, override *UserLogin) (*LoginStep, error)
}

type LoginStartParams struct {
	Override *UserLogin
	HTTP     http.RoundTripper
}

type LoginProcessWithParams interface {
	LoginProcess
	// StartWithParams is a replacement for both Start and StartWithOverride.
	StartWithParams(ctx context.Context, params LoginStartParams) (*LoginStep, error)
}

type LoginProcessDisplayAndWait interface {
	LoginProcess
	// Wait waits for the remote login flow to advance. When a step with
	// CanCancel is cancelled through the provisioning API, ctx is cancelled and
	// context.Cause(ctx) is ErrLoginStepCancelled. The implementation should
	// stop waiting and return ErrLoginStepCancelled.
	Wait(ctx context.Context) (*LoginStep, error)
}

type LoginProcessUserInput interface {
	LoginProcess
	SubmitUserInput(ctx context.Context, input map[string]string) (*LoginStep, error)
}

// LoginProcessStepCancel is implemented by login processes which return
// cancellable steps. CancelStep should perform the back action and return the
// step that the client should display next.
type LoginProcessStepCancel interface {
	LoginProcess
	CancelStep(ctx context.Context) (*LoginStep, error)
}

type LoginProcessCookies interface {
	LoginProcess
	SubmitCookies(ctx context.Context, cookies map[string]string) (*LoginStep, error)
}

type LoginProcessWebAuthn interface {
	LoginProcess
	SubmitWebAuthnResponse(ctx context.Context, response json.RawMessage) (*LoginStep, error)
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
	LoginStepTypeClientHTTP     LoginStepType = "client_http"
	LoginStepTypeDisplayAndWait LoginStepType = "display_and_wait"
	LoginStepTypeWebAuthn       LoginStepType = "webauthn"
	LoginStepTypeComplete       LoginStepType = "complete"
)

type LoginDisplayType string

const (
	LoginDisplayTypeQR      LoginDisplayType = "qr"
	LoginDisplayTypeEmoji   LoginDisplayType = "emoji"
	LoginDisplayTypeCode    LoginDisplayType = "code"
	LoginDisplayTypeNothing LoginDisplayType = "nothing"
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
	// A unique ID for submitting the step. This is randomly generated for every step.
	// It's used to allow safely retrying requests.
	TxnID string `json:"txn_id"`
	// Instructions contains human-readable instructions for completing the login step.
	Instructions string `json:"instructions"`

	// Exactly one of the following structs must be filled depending on the step type.

	DisplayAndWaitParams *LoginDisplayAndWaitParams `json:"display_and_wait,omitempty"`
	CookiesParams        *LoginCookiesParams        `json:"cookies,omitempty"`
	ClientHTTPParams     *LoginClientHTTPParams     `json:"client_http,omitempty"`
	UserInputParams      *LoginUserInputParams      `json:"user_input,omitempty"`
	WebAuthnParams       *LoginWebAuthnParams       `json:"webauthn,omitempty"`
	CompleteParams       *LoginCompleteParams       `json:"complete,omitempty"`
}

func (ls *LoginStep) MarshalZerologObject(e *zerolog.Event) {
	e.Str("type", string(ls.Type)).
		Str("step_id", ls.StepID).
		Str("txn_id", ls.TxnID).
		Str("instructions", ls.Instructions)
	if ls.DisplayAndWaitParams != nil {
		e.Any("display_and_wait", ls.DisplayAndWaitParams)
	}
	if ls.CookiesParams != nil {
		e.Any("cookies", ls.CookiesParams)
	}
	if ls.ClientHTTPParams != nil {
		e.Object("client_http", ls.ClientHTTPParams)
	}
	if ls.UserInputParams != nil {
		e.Any("user_input", ls.UserInputParams)
	}
	if ls.WebAuthnParams != nil {
		e.Any("webauthn", ls.WebAuthnParams)
	}
	if ls.CompleteParams != nil {
		e.Any("complete", ls.CompleteParams)
	}
}

type LoginClientHTTPParams struct {
	RequestID string      `json:"request_id"`
	Method    string      `json:"method"`
	URL       string      `json:"url"`
	Headers   http.Header `json:"headers,omitempty"`
	Body      []byte      `json:"body,omitempty"`
}

func (lchp *LoginClientHTTPParams) MarshalZerologObject(e *zerolog.Event) {
	e.Str("request_id", lchp.RequestID).
		Str("method", lchp.Method).
		Str("url", lchp.URL).
		Int("header_count", len(lchp.Headers)).
		Int("body_length", len(lchp.Body))
}

type LoginClientHTTPResponse struct {
	StatusCode int         `json:"status_code,omitzero"`
	FinalURL   string      `json:"final_url,omitempty"`
	Headers    http.Header `json:"headers,omitempty"`
	Body       []byte      `json:"body,omitempty"`
	Error      string      `json:"error,omitempty"`
}

func (lchr *LoginClientHTTPResponse) IsValid() bool {
	if lchr.Error != "" {
		return true
	}
	return lchr.StatusCode >= 100 && lchr.StatusCode <= 599
}

type LoginWebAuthnParams struct {
	// The origin URL where the credential should be extracted from.
	URL string `json:"url,omitempty"`

	// Standard parameters for https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get
	// Only publicKey seems to be used in practice, so the other options aren't allowed yet.
	PublicKey json.RawMessage `json:"publicKey,omitempty"`
}

type LoginDisplayAndWaitParams struct {
	// The type of thing to display (QR, emoji or text code)
	Type LoginDisplayType `json:"type"`
	// The thing to display (raw data for QR, unicode emoji for emoji, plain string for code, omitted for nothing)
	Data string `json:"data,omitempty"`
	// An image containing the thing to display. If present, this is recommended over using data directly.
	// For emojis, the URL to the canonical image representation of the emoji
	ImageURL string `json:"image_url,omitempty"`
	// If set, the client may allow the user to go back from this step. The
	// context passed to Wait will be cancelled with ErrLoginStepCancelled.
	CanCancel bool `json:"can_cancel,omitzero"`
}

type LoginCookieFieldSourceType string

const (
	LoginCookieTypeCookie        LoginCookieFieldSourceType = "cookie"
	LoginCookieTypeLocalStorage  LoginCookieFieldSourceType = "local_storage"
	LoginCookieTypeRequestHeader LoginCookieFieldSourceType = "request_header"
	LoginCookieTypeRequestBody   LoginCookieFieldSourceType = "request_body"
	LoginCookieTypeSpecial       LoginCookieFieldSourceType = "special"
)

type LoginCookieFieldSource struct {
	// The type of source.
	Type LoginCookieFieldSourceType `json:"type"`
	// The name of the field. The exact meaning depends on the type of source.
	// Cookie:         cookie name
	// Local storage:  key in local storage
	// Request header: header name
	// Request body:   field name inside body after it's parsed (as JSON or multipart form data)
	// Special:        a namespaced identifier that clients can implement special handling for
	Name string `json:"name"`

	// For request header & body types, a regex matching request URLs where the value can be extracted from.
	RequestURLRegex string `json:"request_url_regex,omitempty"`
	// For cookie types, the domain the cookie is present on.
	CookieDomain string `json:"cookie_domain,omitempty"`
}

type LoginCookieField struct {
	// The key in the map that is submitted to the connector.
	ID       string `json:"id"`
	Required bool   `json:"required"`
	// The sources that can be used to acquire the field value. Only one of these needs to be used.
	Sources []LoginCookieFieldSource `json:"sources"`
	// A regex pattern that the client can use to validate value client-side.
	Pattern string `json:"pattern,omitempty"`
}

type LoginCookiesParams struct {
	URL       string `json:"url"`
	UserAgent string `json:"user_agent,omitempty"`

	// The fields that are needed for this cookie login.
	Fields []LoginCookieField `json:"fields"`
	// A JavaScript snippet that can extract some or all of the fields.
	// The snippet will evaluate to a promise that resolves when the relevant fields are found.
	// Fields that are not present in the promise result must be extracted another way.
	ExtractJS string `json:"extract_js,omitempty"`
	// A regex pattern that the URL should match before the client closes the webview.
	//
	// The client may submit the login if the user closes the webview after all cookies are collected
	// even if this URL is not reached, but it should only automatically close the webview after
	// both cookies and the URL match.
	WaitForURLPattern string `json:"wait_for_url_pattern,omitempty"`
	// If set, the client should load the URL and run ExtractJS in a webview that is not shown to the
	// user.
	Hidden bool `json:"hidden,omitzero"`
}

type LoginInputFieldType string

const (
	LoginInputFieldTypeUsername    LoginInputFieldType = "username"
	LoginInputFieldTypePassword    LoginInputFieldType = "password"
	LoginInputFieldTypePhoneNumber LoginInputFieldType = "phone_number"
	LoginInputFieldTypeEmail       LoginInputFieldType = "email"
	LoginInputFieldType2FACode     LoginInputFieldType = "2fa_code"
	LoginInputFieldTypeToken       LoginInputFieldType = "token"
	LoginInputFieldTypeURL         LoginInputFieldType = "url"
	LoginInputFieldTypeDomain      LoginInputFieldType = "domain"
	LoginInputFieldTypeSelect      LoginInputFieldType = "select"
	LoginInputFieldTypeCaptchaCode LoginInputFieldType = "captcha_code"
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
	// A default value that the client can pre-fill the field with.
	DefaultValue string `json:"default_value,omitempty"`
	// A regex pattern that the client can use to validate input client-side.
	Pattern string `json:"pattern,omitempty"`
	// For fields of type select, the valid options.
	// Pattern may also be filled with a regex that matches the same options.
	Options []string `json:"options,omitempty"`
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

func CleanNonInternationalPhoneNumber(phone string) (string, error) {
	phone = numberCleaner.Replace(phone)
	if !isOnlyNumbers(strings.TrimPrefix(phone, "+")) {
		return "", fmt.Errorf("phone number must only contain numbers")
	}
	return phone, nil
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

func noopValidate(input string) (string, error) {
	return input, nil
}

func (f *LoginInputDataField) FillDefaultValidate() {
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
		if f.Pattern != "" {
			f.Validate = func(s string) (string, error) {
				match, err := regexp.MatchString(f.Pattern, s)
				if err != nil {
					return "", err
				} else if !match {
					return "", fmt.Errorf("doesn't match regex `%s`", f.Pattern)
				} else {
					return s, nil
				}
			}
		} else {
			f.Validate = noopValidate
		}
	}
}

type LoginUserInputParams struct {
	// The fields that the user needs to fill in.
	Fields []LoginInputDataField `json:"fields"`

	// Attachments to display alongside the input fields.
	Attachments []*LoginUserInputAttachment `json:"attachments"`

	// If set, the client may allow the user to go back from this step. The login
	// process must implement LoginProcessStepCancel.
	CanCancel bool `json:"can_cancel,omitzero"`
}

type LoginUserInputAttachment struct {
	Type     event.MessageType            `json:"type,omitempty"`
	FileName string                       `json:"filename,omitempty"`
	Content  []byte                       `json:"content,omitempty"`
	Info     LoginUserInputAttachmentInfo `json:"info,omitempty"`
}

type LoginUserInputAttachmentInfo struct {
	MimeType string `json:"mimetype,omitempty"`
	Width    int    `json:"w,omitzero"`
	Height   int    `json:"h,omitzero"`
	Size     int    `json:"size,omitzero"`
}

type LoginCompleteParams struct {
	UserLoginID networkid.UserLoginID `json:"user_login_id"`
	UserLogin   *UserLogin            `json:"-"`
}

type LoginSubmit struct {
}
