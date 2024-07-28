// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unsafe"

	"github.com/rs/zerolog"
	"go.mau.fi/util/jsontime"
	"golang.org/x/exp/slices"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
)

type exchangeTokenData struct {
	Token string `json:"token"`
}

type jwtPayload struct {
	Subject    id.UserID     `json:"sub"`
	Expiration jsontime.Unix `json:"exp"`
	Issuer     string        `json:"iss"`
	Audience   []string      `json:"aud"`
}

const defaultJWTHeader = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.` // {"alg":"HS256","typ":"JWT"}

func (prov *ProvisioningAPI) makeJWT(userID id.UserID, validity time.Duration) string {
	payload, err := json.Marshal(&jwtPayload{
		Subject:    userID,
		Expiration: jsontime.U(time.Now().Add(validity)),
		Issuer:     prov.br.Bot.UserID.String(),
		Audience:   []string{prov.br.Bot.UserID.String()},
	})
	if err != nil {
		return ""
	}
	payloadLen := base64.RawURLEncoding.EncodedLen(len(payload))
	data := make([]byte, len(defaultJWTHeader)+payloadLen+33)
	copy(data, defaultJWTHeader)
	base64.RawURLEncoding.Encode(data[len(defaultJWTHeader):], payload)
	hasher := hmac.New(sha256.New, []byte(prov.br.Config.Provisioning.SharedSecret))
	hasher.Write(data[:len(defaultJWTHeader)+payloadLen])
	base64.RawURLEncoding.Encode(data[len(defaultJWTHeader)+payloadLen:], hasher.Sum(nil))
	return unsafe.String(unsafe.SliceData(data), len(data))
}

func (prov *ProvisioningAPI) validateJWT(jwt string) (id.UserID, error) {
	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT")
	} else if parts[0] != defaultJWTHeader[:len(defaultJWTHeader)-1] {
		return "", fmt.Errorf("invalid JWT header")
	}
	checksum, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT checksum: %w", err)
	}
	hasher := hmac.New(sha256.New, []byte(prov.br.Config.Provisioning.SharedSecret))
	hasher.Write([]byte(jwt[:len(defaultJWTHeader)+len(parts[1])]))
	if !hmac.Equal(checksum, hasher.Sum(nil)) {
		return "", fmt.Errorf("invalid JWT checksum")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}
	var payload jwtPayload
	err = json.Unmarshal(payloadBytes, &payload)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal JWT payload: %w", err)
	} else if payload.Expiration.Before(time.Now()) {
		return "", fmt.Errorf("JWT has expired")
	} else if !slices.Contains(payload.Audience, prov.br.Bot.UserID.String()) {
		return "", fmt.Errorf("invalid JWT audience")
	}
	return payload.Subject, nil
}

func (prov *ProvisioningAPI) checkJWTAuth(expectedUserID id.UserID, jwt string) error {
	userID, err := prov.validateJWT(jwt)
	if err != nil {
		return err
	}
	if userID != expectedUserID {
		return fmt.Errorf("mismatching user ID (%q != %q)", userID, expectedUserID)
	}
	return nil
}

func (prov *ProvisioningAPI) PostExchangeToken(w http.ResponseWriter, r *http.Request) {
	var reqData exchangeTokenData
	err := json.NewDecoder(r.Body).Decode(&reqData)
	if err != nil {
		jsonResponse(w, http.StatusBadRequest, &mautrix.RespError{
			Err:     "Failed to decode request body",
			ErrCode: mautrix.MNotJSON.ErrCode,
		})
		return
	}
	userID := id.UserID(r.URL.Query().Get("user_id"))
	homeserver := userID.Homeserver()
	if homeserver == prov.br.AS.HomeserverDomain {
		jsonResponse(w, http.StatusForbidden, &mautrix.RespError{
			Err:     "Local users can't exchange tokens",
			ErrCode: mautrix.MForbidden.ErrCode,
		})
		return
	}
	perms := prov.br.Config.Bridge.Permissions.Get(userID)
	// TODO separate permissions for provisioning API?
	if !perms.Commands {
		jsonResponse(w, http.StatusForbidden, &mautrix.RespError{
			Err:     "User does not have permission to use the provisioning API",
			ErrCode: mautrix.MForbidden.ErrCode,
		})
		return
	}
	err = prov.validateOpenIDToken(r.Context(), userID, reqData.Token)
	if err != nil {
		zerolog.Ctx(r.Context()).Warn().Err(err).Msg("Failed to validate OpenID token")
		jsonResponse(w, http.StatusUnauthorized, &mautrix.RespError{
			Err:     "Failed to validate token",
			ErrCode: mautrix.MUnknownToken.ErrCode,
		})
		return
	}
	jsonResponse(w, http.StatusOK, &exchangeTokenData{
		Token: prov.makeJWT(userID, 24*time.Hour),
	})
}

type respOpenIDUserInfo struct {
	Sub id.UserID `json:"sub"`
}

func (prov *ProvisioningAPI) validateOpenIDToken(ctx context.Context, userID id.UserID, token string) error {
	reqURL := url.URL{
		Scheme: "matrix-federation",
		Host:   userID.Homeserver(),
		Path:   "/_matrix/federation/v1/openid/userinfo",
		RawQuery: (&url.Values{
			"access_token": {token},
		}).Encode(),
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to prepare request: %w", err)
	}
	resp, err := prov.fedClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
	var respData respOpenIDUserInfo
	err = json.NewDecoder(resp.Body).Decode(&respData)
	if err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	} else if respData.Sub != userID {
		return fmt.Errorf("mismatching user ID (%q != %q)", respData.Sub, userID)
	}
	return nil
}
