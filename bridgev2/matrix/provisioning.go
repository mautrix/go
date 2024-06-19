// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/xid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"go.mau.fi/util/requestlog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/id"
)

type matrixAuthCacheEntry struct {
	Expires time.Time
	UserID  id.UserID
}

type ProvisioningAPI struct {
	br  *Connector
	log zerolog.Logger
	net bridgev2.NetworkConnector

	logins     map[string]*ProvLogin
	loginsLock sync.RWMutex

	matrixAuthCache     map[string]matrixAuthCacheEntry
	matrixAuthCacheLock sync.Mutex
}

type ProvLogin struct {
	ID       string
	Process  bridgev2.LoginProcess
	NextStep *bridgev2.LoginStep
	Lock     sync.Mutex
}

type provisioningContextKey int

const (
	provisioningUserKey provisioningContextKey = iota
	provisioningUserLoginKey
	provisioningLoginProcessKey
)

func (prov *ProvisioningAPI) Init() {
	prov.matrixAuthCache = make(map[string]matrixAuthCacheEntry)
	prov.logins = make(map[string]*ProvLogin)
	prov.net = prov.br.Bridge.Network
	prov.log = prov.br.Log.With().Str("component", "provisioning").Logger()
	router := prov.br.AS.Router.PathPrefix(prov.br.Config.Provisioning.Prefix).Subrouter()
	router.Use(hlog.NewHandler(prov.log))
	router.Use(requestlog.AccessLogger(false))
	router.Use(prov.AuthMiddleware)
	router.Path("/v3/login/flows").Methods(http.MethodGet).HandlerFunc(prov.GetLoginFlows)
	router.Path("/v3/login/start/{flowID}").Methods(http.MethodPost).HandlerFunc(prov.PostLoginStart)
	router.Path("/v3/login/step/{loginProcessID}/{stepID}/{stepType:user_input|cookies}").Methods(http.MethodPost).HandlerFunc(prov.PostLoginSubmitInput)
	router.Path("/v3/login/step/{loginProcessID}/{stepID}/{stepType:wait}").Methods(http.MethodPost).HandlerFunc(prov.PostLoginWait)
	router.Path("/v3/resolve_identifier/{identifier}").Methods(http.MethodGet).HandlerFunc(prov.GetResolveIdentifier)
	router.Path("/v3/create_dm").Methods(http.MethodPost).HandlerFunc(prov.PostCreateDM)
	router.Path("/v3/create_group").Methods(http.MethodPost).HandlerFunc(prov.PostCreateGroup)

	if prov.br.Config.Provisioning.DebugEndpoints {
		prov.log.Debug().Msg("Enabling debug API at /debug")
		r := prov.br.AS.Router.PathPrefix("/debug").Subrouter()
		r.Use(prov.AuthMiddleware)
		r.PathPrefix("/pprof").Handler(http.DefaultServeMux)
	}
}

func jsonResponse(w http.ResponseWriter, status int, response any) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(response)
}

func (prov *ProvisioningAPI) checkMatrixAuth(ctx context.Context, userID id.UserID, token string) error {
	prov.matrixAuthCacheLock.Lock()
	defer prov.matrixAuthCacheLock.Unlock()
	if cached, ok := prov.matrixAuthCache[token]; ok && cached.Expires.After(time.Now()) && cached.UserID == userID {
		return nil
	} else if client, err := prov.br.DoublePuppet.newClient(ctx, userID, token); err != nil {
		return err
	} else if whoami, err := client.Whoami(ctx); err != nil {
		return err
	} else if whoami.UserID != userID {
		return fmt.Errorf("mismatching user ID (%q != %q)", whoami.UserID, userID)
	} else {
		prov.matrixAuthCache[token] = matrixAuthCacheEntry{
			Expires: time.Now().Add(5 * time.Minute),
			UserID:  whoami.UserID,
		}
		return nil
	}
}

func (prov *ProvisioningAPI) AuthMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		userID := id.UserID(r.URL.Query().Get("user_id"))
		if auth != prov.br.Config.Provisioning.SharedSecret {
			err := prov.checkMatrixAuth(r.Context(), userID, auth)
			if err != nil {
				zerolog.Ctx(r.Context()).Warn().Err(err).
					Msg("Provisioning API request contained invalid auth")
				jsonResponse(w, http.StatusForbidden, &mautrix.RespError{
					Err:     "Invalid auth token",
					ErrCode: mautrix.MForbidden.ErrCode,
				})
				return
			}
		}
		user, err := prov.br.Bridge.GetUserByMXID(r.Context(), userID)
		if err != nil {
			zerolog.Ctx(r.Context()).Err(err).Msg("Failed to get user")
			jsonResponse(w, http.StatusInternalServerError, &mautrix.RespError{
				Err:     "Failed to get user",
				ErrCode: "M_UNKNOWN",
			})
			return
		}
		// TODO handle user being nil?

		ctx := context.WithValue(r.Context(), provisioningUserKey, user)
		if loginID, ok := mux.Vars(r)["loginProcessID"]; ok {
			prov.loginsLock.RLock()
			login, ok := prov.logins[loginID]
			prov.loginsLock.RUnlock()
			if !ok {
				zerolog.Ctx(r.Context()).Warn().Str("login_id", loginID).Msg("Login not found")
				jsonResponse(w, http.StatusNotFound, &mautrix.RespError{
					Err:     "Login not found",
					ErrCode: mautrix.MNotFound.ErrCode,
				})
				return
			}
			login.Lock.Lock()
			// This will only unlock after the handler runs
			defer login.Lock.Unlock()
			stepID := mux.Vars(r)["stepID"]
			if login.NextStep.StepID != stepID {
				zerolog.Ctx(r.Context()).Warn().
					Str("request_step_id", stepID).
					Str("expected_step_id", login.NextStep.StepID).
					Msg("Step ID does not match")
				jsonResponse(w, http.StatusBadRequest, &mautrix.RespError{
					Err:     "Step ID does not match",
					ErrCode: mautrix.MBadState.ErrCode,
				})
				return
			}
			stepType := mux.Vars(r)["stepType"]
			if login.NextStep.Type != bridgev2.LoginStepType(stepType) {
				zerolog.Ctx(r.Context()).Warn().
					Str("request_step_type", stepType).
					Str("expected_step_type", string(login.NextStep.Type)).
					Msg("Step type does not match")
				jsonResponse(w, http.StatusBadRequest, &mautrix.RespError{
					Err:     "Step type does not match",
					ErrCode: mautrix.MBadState.ErrCode,
				})
				return
			}
			ctx = context.WithValue(r.Context(), provisioningLoginProcessKey, login)
		}
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

type RespLoginFlows struct {
	Flows []bridgev2.LoginFlow `json:"flows"`
}

type RespSubmitLogin struct {
	LoginID string `json:"login_id"`
	*bridgev2.LoginStep
}

func (prov *ProvisioningAPI) GetLoginFlows(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, &RespLoginFlows{
		Flows: prov.net.GetLoginFlows(),
	})
}

func (prov *ProvisioningAPI) PostLoginStart(w http.ResponseWriter, r *http.Request) {
	login, err := prov.net.CreateLogin(
		r.Context(),
		r.Context().Value(provisioningUserKey).(*bridgev2.User),
		mux.Vars(r)["flowID"],
	)
	if err != nil {
		zerolog.Ctx(r.Context()).Err(err).Msg("Failed to create login process")
		jsonResponse(w, http.StatusInternalServerError, &mautrix.RespError{
			Err:     "Failed to create login process",
			ErrCode: "M_UNKNOWN",
		})
		return
	}
	firstStep, err := login.Start(r.Context())
	if err != nil {
		zerolog.Ctx(r.Context()).Err(err).Msg("Failed to start login")
		jsonResponse(w, http.StatusInternalServerError, &mautrix.RespError{
			Err:     "Failed to start login",
			ErrCode: "M_UNKNOWN",
		})
		return
	}
	loginID := xid.New().String()
	prov.loginsLock.Lock()
	prov.logins[loginID] = &ProvLogin{
		ID:       loginID,
		Process:  login,
		NextStep: firstStep,
	}
	prov.loginsLock.Unlock()
	jsonResponse(w, http.StatusOK, &RespSubmitLogin{LoginID: loginID, LoginStep: firstStep})
}

func (prov *ProvisioningAPI) PostLoginSubmitInput(w http.ResponseWriter, r *http.Request) {
	var params map[string]string
	err := json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		zerolog.Ctx(r.Context()).Err(err).Msg("Failed to decode request body")
		jsonResponse(w, http.StatusBadRequest, &mautrix.RespError{
			Err:     "Failed to decode request body",
			ErrCode: mautrix.MNotJSON.ErrCode,
		})
		return
	}
	login := r.Context().Value(provisioningLoginProcessKey).(*ProvLogin)
	var nextStep *bridgev2.LoginStep
	switch login.NextStep.Type {
	case bridgev2.LoginStepTypeUserInput:
		nextStep, err = login.Process.(bridgev2.LoginProcessUserInput).SubmitUserInput(r.Context(), params)
	case bridgev2.LoginStepTypeCookies:
		nextStep, err = login.Process.(bridgev2.LoginProcessCookies).SubmitCookies(r.Context(), params)
	default:
		panic("Impossible state")
	}
	if err != nil {
		zerolog.Ctx(r.Context()).Err(err).Msg("Failed to submit input")
		jsonResponse(w, http.StatusInternalServerError, &mautrix.RespError{
			Err:     "Failed to submit input",
			ErrCode: "M_UNKNOWN",
		})
		return
	}
	login.NextStep = nextStep
	jsonResponse(w, http.StatusOK, &RespSubmitLogin{LoginID: login.ID, LoginStep: nextStep})
}

func (prov *ProvisioningAPI) PostLoginWait(w http.ResponseWriter, r *http.Request) {
	login := r.Context().Value(provisioningLoginProcessKey).(*ProvLogin)
	nextStep, err := login.Process.(bridgev2.LoginProcessDisplayAndWait).Wait(r.Context())
	if err != nil {
		zerolog.Ctx(r.Context()).Err(err).Msg("Failed to submit input")
		jsonResponse(w, http.StatusInternalServerError, &mautrix.RespError{
			Err:     "Failed to submit input",
			ErrCode: "M_UNKNOWN",
		})
		return
	}
	login.NextStep = nextStep
	jsonResponse(w, http.StatusOK, &RespSubmitLogin{LoginID: login.ID, LoginStep: nextStep})
}

func (prov *ProvisioningAPI) getLoginForCall(w http.ResponseWriter, r *http.Request) *bridgev2.UserLogin {
	user := r.Context().Value(provisioningUserKey).(*bridgev2.User)
	userLogin := prov.br.Bridge.GetCachedUserLoginByID(networkid.UserLoginID(r.URL.Query().Get("login_id")))
	if userLogin == nil || userLogin.UserMXID != user.MXID {
		userLogin = user.GetDefaultLogin()
	}
	if userLogin == nil {
		jsonResponse(w, http.StatusBadRequest, &mautrix.RespError{
			Err:     "Not logged in",
			ErrCode: "FI.MAU.NOT_LOGGED_IN",
		})
		return nil
	}
	return userLogin
}

type RespResolveIdentifier struct {
	ID        networkid.UserID    `json:"id,omitempty"`
	Name      string              `json:"name,omitempty"`
	AvatarURL id.ContentURIString `json:"avatar_url,omitempty"`
	MXID      id.UserID           `json:"mxid,omitempty"`
	DMRoomID  id.RoomID           `json:"dm_room_mxid,omitempty"`
}

func (prov *ProvisioningAPI) doResolveIdentifier(w http.ResponseWriter, r *http.Request, createChat bool) {
	login := prov.getLoginForCall(w, r)
	if login == nil {
		return
	}
	api, ok := login.Client.(bridgev2.IdentifierResolvingNetworkAPI)
	if !ok {
		jsonResponse(w, http.StatusNotImplemented, &mautrix.RespError{
			Err:     "This bridge does not support resolving identifiers",
			ErrCode: mautrix.MUnrecognized.ErrCode,
		})
		return
	}
	resp, err := api.ResolveIdentifier(r.Context(), mux.Vars(r)["identifier"], createChat)
	if err != nil {
		zerolog.Ctx(r.Context()).Err(err).Msg("Failed to resolve identifier")
		jsonResponse(w, http.StatusNotImplemented, &mautrix.RespError{
			Err:     fmt.Sprintf("Failed to resolve identifier: %v", err),
			ErrCode: "M_UNKNOWN",
		})
	}
	apiResp := &RespResolveIdentifier{}
	status := http.StatusOK
	if resp.Ghost != nil {
		if resp.UserInfo != nil {
			resp.Ghost.UpdateInfo(r.Context(), resp.UserInfo)
		}
		apiResp.Name = resp.Ghost.Name
		apiResp.AvatarURL = resp.Ghost.AvatarMXC
		apiResp.MXID = resp.Ghost.MXID
	} else if resp.UserInfo != nil && resp.UserInfo.Name != nil {
		apiResp.Name = *resp.UserInfo.Name
	}
	if resp.Chat != nil {
		if resp.Chat.Portal == nil {
			resp.Chat.Portal, err = prov.br.Bridge.GetPortalByID(r.Context(), resp.Chat.PortalID)
			if err != nil {
				zerolog.Ctx(r.Context()).Err(err).Msg("Failed to get portal")
				jsonResponse(w, http.StatusNotImplemented, &mautrix.RespError{
					Err:     "Failed to get portal",
					ErrCode: "M_UNKNOWN",
				})
				return
			}
		}
		if createChat && resp.Chat.Portal.MXID == "" {
			status = http.StatusCreated
			err = resp.Chat.Portal.CreateMatrixRoom(r.Context(), login, resp.Chat.PortalInfo)
			if err != nil {
				zerolog.Ctx(r.Context()).Err(err).Msg("Failed to create portal room")
				jsonResponse(w, http.StatusNotImplemented, &mautrix.RespError{
					Err:     "Failed to create portal room",
					ErrCode: "M_UNKNOWN",
				})
				return
			}
		}
		apiResp.DMRoomID = resp.Chat.Portal.MXID
	}
	jsonResponse(w, status, resp)
}

func (prov *ProvisioningAPI) GetResolveIdentifier(w http.ResponseWriter, r *http.Request) {
	prov.doResolveIdentifier(w, r, false)
}

func (prov *ProvisioningAPI) PostCreateDM(w http.ResponseWriter, r *http.Request) {
	prov.doResolveIdentifier(w, r, true)
}

func (prov *ProvisioningAPI) PostCreateGroup(w http.ResponseWriter, r *http.Request) {
	login := prov.getLoginForCall(w, r)
	if login == nil {
		return
	}
	jsonResponse(w, http.StatusNotImplemented, &mautrix.RespError{
		Err:     "Creating groups is not yet implemented",
		ErrCode: mautrix.MUnrecognized.ErrCode,
	})
}
