// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/mux"
	"github.com/rs/xid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/rs/zerolog/log"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/id"
)

type ProvisioningAPI struct {
	br  *Connector
	log zerolog.Logger
	net bridgev2.NetworkConnector

	logins     map[string]*ProvLogin
	loginsLock sync.RWMutex
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
	provisioningLoginKey
)

func (prov *ProvisioningAPI) Init() {
	prov.net = prov.br.Bridge.Network
	prov.log = prov.br.Log.With().Str("component", "provisioning").Logger()
	router := prov.br.AS.Router.PathPrefix(prov.br.Config.Provisioning.Prefix).Subrouter()
	router.Use(hlog.NewHandler(prov.log))
	// TODO add access logger
	//router.Use(requestlog.AccessLogger(true))
	router.Use(prov.AuthMiddleware)
	router.Path("/v3/login/flows").Methods(http.MethodGet).HandlerFunc(prov.GetLoginFlows)
	router.Path("/v3/login/start/{flowID}").Methods(http.MethodPost).HandlerFunc(prov.PostLoginStart)
	router.Path("/v3/login/step/{loginID}/{stepID}/{stepType:user_input|cookies}").Methods(http.MethodPost).HandlerFunc(prov.PostLoginSubmitInput)
	router.Path("/v3/login/step/{loginID}/{stepID}/{stepType:wait}").Methods(http.MethodPost).HandlerFunc(prov.PostLoginWait)

	if prov.br.Config.Provisioning.DebugEndpoints {
		log.Debug().Msg("Enabling debug API at /debug")
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

func (prov *ProvisioningAPI) AuthMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if auth != prov.br.Config.Provisioning.SharedSecret {
			zerolog.Ctx(r.Context()).Warn().Msg("Authentication token does not match shared secret")
			jsonResponse(w, http.StatusForbidden, &mautrix.RespError{
				Err:     "Authentication token does not match shared secret",
				ErrCode: mautrix.MForbidden.ErrCode,
			})
			return
		}
		userID := r.URL.Query().Get("user_id")
		user, err := prov.br.Bridge.GetUserByMXID(r.Context(), id.UserID(userID))
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
		if loginID, ok := mux.Vars(r)["loginID"]; ok {
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
			ctx = context.WithValue(r.Context(), provisioningLoginKey, login)
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
	login := r.Context().Value(provisioningLoginKey).(*ProvLogin)
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
	login := r.Context().Value(provisioningLoginKey).(*ProvLogin)
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
