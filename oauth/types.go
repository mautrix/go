// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package oauth

import (
	"fmt"
	"strings"

	"go.mau.fi/util/exslices"
	"go.mau.fi/util/jsontime"

	"maunium.net/go/mautrix/id"
)

type AccountManagementAction string

const (
	AccountManagementActionProfile           AccountManagementAction = "org.matrix.profile"
	AccountManagementActionDeviceList        AccountManagementAction = "org.matrix.devices_list"
	AccountManagementActionDeviceView        AccountManagementAction = "org.matrix.device_view"
	AccountManagementActionDeviceDelete      AccountManagementAction = "org.matrix.device_delete"
	AccountManagementActionCrossSigningReset AccountManagementAction = "org.matrix.cross_signing_reset"
	AccountManagementActionSessionList       AccountManagementAction = "org.matrix.sessions_list"
	AccountManagementActionSessionView       AccountManagementAction = "org.matrix.session_view"
	AccountManagementActionSessionEnd        AccountManagementAction = "org.matrix.session_end"
	AccountManagementActionAccountDeactivate AccountManagementAction = "org.matrix.account_deactivate"
)

type PromptValue string

const (
	PromptValueLogin  PromptValue = "login"
	PromptValueCreate PromptValue = "create"
)

type ResponseMode string

const (
	ResponseModeQuery    ResponseMode = "query"
	ResponseModeFragment ResponseMode = "fragment"
	ResponseModeFormPost ResponseMode = "form_post"
)

type ResponseType string

const (
	ResponseTypeCode    ResponseType = "code"
	ResponseTypeIDToken ResponseType = "id_token"
)

type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeRefreshToken      GrantType = "refresh_token"
	GrantTypeClientCredentials GrantType = "client_credentials"
	GrantTypeDeviceCode        GrantType = "urn:ietf:params:oauth:grant-type:device_code"
)

type Scope string

const (
	ScopeOpenID    Scope = "openid"
	ScopeEmail     Scope = "email"
	ScopeClientAPI Scope = "urn:matrix:client:api:*"
)

func ScopeDevice(deviceID id.DeviceID) Scope {
	return Scope(fmt.Sprintf("urn:matrix:client:device:%s", deviceID))
}

type SubjectType string

const (
	SubjectTypePublic SubjectType = "public"
)

type DisplayValue string

const (
	DisplayValuePage DisplayValue = "page"
)

type CodeChallengeMethod string

const (
	CodeChallengeMethodS256  CodeChallengeMethod = "S256"
	CodeChallengeMethodPlain CodeChallengeMethod = "plain"
)

type AuthMethod string

const (
	AuthMethodClientSecretPost  AuthMethod = "client_secret_post"
	AuthMethodClientSecretBasic AuthMethod = "client_secret_basic"
	AuthMethodClientSecretJWT   AuthMethod = "client_secret_jwt"
	AuthMethodPrivateKeyJWT     AuthMethod = "private_key_jwt"
	AuthMethodNone              AuthMethod = "none"
)

type Algorithm string

const (
	AlgorithmHS256  Algorithm = "HS256"
	AlgorithmHS384  Algorithm = "HS384"
	AlgorithmHS512  Algorithm = "HS512"
	AlgorithmRS256  Algorithm = "RS256"
	AlgorithmRS384  Algorithm = "RS384"
	AlgorithmRS512  Algorithm = "RS512"
	AlgorithmPS256  Algorithm = "PS256"
	AlgorithmPS384  Algorithm = "PS384"
	AlgorithmPS512  Algorithm = "PS512"
	AlgorithmES256  Algorithm = "ES256"
	AlgorithmES384  Algorithm = "ES384"
	AlgorithmES256K Algorithm = "ES256K"
)

type ClaimType string

const (
	ClaimTypeNormal ClaimType = "normal"
)

type Claim string

const (
	ClaimIssuer          Claim = "iss"
	ClaimSubject         Claim = "sub"
	ClaimAudience        Claim = "aud"
	ClaimIssuedAt        Claim = "iat"
	ClaimExpiresAt       Claim = "exp"
	ClaimNonce           Claim = "nonce"
	ClaimAuthTime        Claim = "auth_time"
	ClaimAccessTokenHash Claim = "at_hash"
	ClaimAuthCodeHash    Claim = "c_hash"
)

type ServerMetadata struct {
	Issuer                        string                `json:"issuer"`
	AuthorizationEndpoint         string                `json:"authorization_endpoint"`
	RegistrationEndpoint          string                `json:"registration_endpoint"`
	ResponseTypesSupported        []ResponseType        `json:"response_types_supported"`
	ResponseModesSupported        []ResponseMode        `json:"response_modes_supported"`
	GrantTypesSupported           []GrantType           `json:"grant_types_supported"`
	CodeChallengeMethodsSupported []CodeChallengeMethod `json:"code_challenge_methods_supported"`

	ScopesSupported                   []Scope        `json:"scopes_supported,omitempty"`
	TokenEndpoint                     string         `json:"token_endpoint,omitempty"`
	JWKsURI                           string         `json:"jwks_uri,omitempty"`
	AccountManagementURI              string         `json:"account_management_uri,omitempty"`
	UserInfoEndpoint                  string         `json:"userinfo_endpoint,omitempty"`
	SubjectTypesSupported             []SubjectType  `json:"subject_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported  []Algorithm    `json:"id_token_signing_alg_values_supported,omitempty"`
	UserInfoSigningAlgValuesSupported []Algorithm    `json:"userinfo_signing_alg_values_supported,omitempty"`
	DisplayValuesSupported            []DisplayValue `json:"display_values_supported,omitempty"`
	ClaimTypesSupported               []ClaimType    `json:"claim_types_supported,omitempty"`
	ClaimsSupported                   []Claim        `json:"claims_supported,omitempty"`
	ClaimsParameterSupported          bool           `json:"claims_parameter_supported,omitempty"`
	RequestParameterSupported         bool           `json:"request_parameter_supported,omitempty"`
	RequestURIParameterSupported      bool           `json:"request_uri_parameter_supported,omitempty"`
	PromptValuesSupported             []PromptValue  `json:"prompt_values_supported,omitempty"`
	DeviceAuthorizationEndpoint       string         `json:"device_authorization_endpoint,omitempty"`

	AccountManagementActionsSupported []AccountManagementAction `json:"account_management_actions_supported,omitempty"`

	TokenEndpointAuthMethodsSupported          []AuthMethod `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported []Algorithm  `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`

	RevocationEndpoint                              string       `json:"revocation_endpoint"`
	RevocationEndpointAuthMethodsSupported          []AuthMethod `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthSigningAlgValuesSupported []Algorithm  `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`

	IntrospectionEndpoint                              string       `json:"introspection_endpoint,omitempty"`
	IntrospectionEndpointAuthMethodsSupported          []AuthMethod `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointAuthSigningAlgValuesSupported []Algorithm  `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`

	MASGraphQLEndpoint string `json:"org.matrix.matrix-authentication-service.graphql_endpoint,omitempty"`
}

type ApplicationType string

const (
	ApplicationTypeNative ApplicationType = "native"
	ApplicationTypeWeb    ApplicationType = "web"
)

type ClientMetadata struct {
	// This is only set in the response by the server
	ClientID string `json:"client_id,omitempty"`

	ApplicationType ApplicationType `json:"application_type,omitempty"`

	ClientName string `json:"client_name,omitempty"`
	ClientURI  string `json:"client_uri"`
	LogoURI    string `json:"logo_uri,omitempty"`
	PolicyURI  string `json:"policy_uri,omitempty"`
	TOSURI     string `json:"tos_uri,omitempty"`

	GrantTypes    []GrantType    `json:"grant_types,omitempty"`
	RedirectURIs  []string       `json:"redirect_uris,omitempty"`
	ResponseTypes []ResponseType `json:"response_types,omitempty"`

	TokenEndpointAuthMethod AuthMethod `json:"token_endpoint_auth_method,omitempty"`

	Extra map[string]any `json:",unknown"`
}

type TokenResponse struct {
	AccessToken  string           `json:"access_token"`
	TokenType    string           `json:"token_type"`
	ExpiresIn    jsontime.Seconds `json:"expires_in"`
	RefreshToken string           `json:"refresh_token,omitempty"`
}

type ScopeList []Scope

func (sl ScopeList) String() string {
	return strings.Join(exslices.CastToString[string](sl), " ")
}

type GetAuthorizationURLParams struct {
	RedirectURI  string       `json:"redirect_uri"`
	Scopes       ScopeList    `json:"scopes"`
	UserIDHint   id.UserID    `json:"user_id_hint,omitempty"`
	ClientID     string       `json:"client_id,omitempty"`
	ResponseMode ResponseMode `json:"response_mode,omitempty"`
}

type GenerateDeviceCodeParams struct {
	Scopes     ScopeList `json:"scopes"`
	UserIDHint id.UserID `json:"user_id_hint,omitempty"`
	ClientID   string    `json:"client_id,omitempty"`
}

type AuthorizationCodeResponse struct {
	State        string `json:"state"`
	CodeVerifier string `json:"code_verifier"`
	URL          string `json:"url"`
}

type ExchangeTokenParams struct {
	CodeVerifier string `json:"code_verifier"`
	RedirectURI  string `json:"redirect_uri"`
	Code         string `json:"code"`
	ClientID     string `json:"client_id,omitempty"`

	StoreCredentials bool `json:"-"`
}

type DeviceCodeResponse struct {
	DeviceCode              string           `json:"device_code"`
	UserCode                string           `json:"user_code"`
	VerificationURI         string           `json:"verification_uri"`
	VerificationURIComplete string           `json:"verification_uri_complete,omitempty"`
	ExpiresIn               jsontime.Seconds `json:"expires_in"`
	Interval                jsontime.Seconds `json:"interval,omitzero"`
}

type PollDeviceCodeParams struct {
	DeviceCode       string `json:"device_code"`
	ClientID         string `json:"client_id,omitempty"`
	StoreCredentials bool   `json:"-"`
}
