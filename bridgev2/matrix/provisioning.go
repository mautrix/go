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
	"go.mau.fi/util/jsontime"
	"go.mau.fi/util/requestlog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridge/status"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"
)

type matrixAuthCacheEntry struct {
	Expires time.Time
	UserID  id.UserID
}

type ProvisioningAPI struct {
	Router *mux.Router

	br  *Connector
	log zerolog.Logger
	net bridgev2.NetworkConnector

	fedClient *federation.Client

	logins     map[string]*ProvLogin
	loginsLock sync.RWMutex

	matrixAuthCache     map[string]matrixAuthCacheEntry
	matrixAuthCacheLock sync.Mutex
}

type ProvLogin struct {
	ID       string
	Process  bridgev2.LoginProcess
	NextStep *bridgev2.LoginStep
	Override *bridgev2.UserLogin
	Lock     sync.Mutex
}

type provisioningContextKey int

const (
	provisioningUserKey provisioningContextKey = iota
	provisioningUserLoginKey
	provisioningLoginProcessKey
)

func (prov *ProvisioningAPI) GetUser(r *http.Request) *bridgev2.User {
	return r.Context().Value(provisioningUserKey).(*bridgev2.User)
}

func (prov *ProvisioningAPI) GetRouter() *mux.Router {
	return prov.Router
}

type IProvisioningAPI interface {
	GetRouter() *mux.Router
	GetUser(r *http.Request) *bridgev2.User
}

func (br *Connector) GetProvisioning() IProvisioningAPI {
	return br.Provisioning
}

func (prov *ProvisioningAPI) Init() {
	prov.matrixAuthCache = make(map[string]matrixAuthCacheEntry)
	prov.logins = make(map[string]*ProvLogin)
	prov.net = prov.br.Bridge.Network
	prov.log = prov.br.Log.With().Str("component", "provisioning").Logger()
	prov.fedClient = federation.NewClient("", nil)
	prov.fedClient.HTTP.Timeout = 20 * time.Second
	tp := prov.fedClient.HTTP.Transport.(*federation.ServerResolvingTransport)
	tp.Dialer.Timeout = 10 * time.Second
	tp.Transport.ResponseHeaderTimeout = 10 * time.Second
	tp.Transport.TLSHandshakeTimeout = 10 * time.Second
	prov.Router = prov.br.AS.Router.PathPrefix(prov.br.Config.Provisioning.Prefix).Subrouter()
	prov.Router.Use(hlog.NewHandler(prov.log))
	prov.Router.Use(corsMiddleware)
	prov.Router.Use(requestlog.AccessLogger(false))
	prov.Router.Use(prov.AuthMiddleware)
	prov.Router.Path("/v3/whoami").Methods(http.MethodGet, http.MethodOptions).HandlerFunc(prov.GetWhoami)
	prov.Router.Path("/v3/login/flows").Methods(http.MethodGet, http.MethodOptions).HandlerFunc(prov.GetLoginFlows)
	prov.Router.Path("/v3/login/start/{flowID}").Methods(http.MethodPost, http.MethodOptions).HandlerFunc(prov.PostLoginStart)
	prov.Router.Path("/v3/login/step/{loginProcessID}/{stepID}/{stepType:user_input|cookies}").Methods(http.MethodPost, http.MethodOptions).HandlerFunc(prov.PostLoginSubmitInput)
	prov.Router.Path("/v3/login/step/{loginProcessID}/{stepID}/{stepType:display_and_wait}").Methods(http.MethodPost, http.MethodOptions).HandlerFunc(prov.PostLoginWait)
	prov.Router.Path("/v3/logout/{loginID}").Methods(http.MethodPost, http.MethodOptions).HandlerFunc(prov.PostLogout)
	prov.Router.Path("/v3/logins").Methods(http.MethodGet, http.MethodOptions).HandlerFunc(prov.GetLogins)
	prov.Router.Path("/v3/contacts").Methods(http.MethodGet, http.MethodOptions).HandlerFunc(prov.GetContactList)
	prov.Router.Path("/v3/resolve_identifier/{identifier}").Methods(http.MethodGet, http.MethodOptions).HandlerFunc(prov.GetResolveIdentifier)
	prov.Router.Path("/v3/create_dm/{identifier}").Methods(http.MethodPost, http.MethodOptions).HandlerFunc(prov.PostCreateDM)
	prov.Router.Path("/v3/create_group").Methods(http.MethodPost, http.MethodOptions).HandlerFunc(prov.PostCreateGroup)

	if prov.br.Config.Provisioning.DebugEndpoints {
		prov.log.Debug().Msg("Enabling debug API at /debug")
		r := prov.br.AS.Router.PathPrefix("/debug").Subrouter()
		r.Use(prov.AuthMiddleware)
		r.PathPrefix("/pprof").Handler(http.DefaultServeMux)
	}
}

func corsMiddleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		handler.ServeHTTP(w, r)
	})
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

func (prov *ProvisioningAPI) checkFederatedMatrixAuth(ctx context.Context, userID id.UserID, token string) error {
	homeserver := userID.Homeserver()
	wrappedToken := fmt.Sprintf("%s:%s", homeserver, token)
	// TODO smarter locking
	prov.matrixAuthCacheLock.Lock()
	defer prov.matrixAuthCacheLock.Unlock()
	if cached, ok := prov.matrixAuthCache[wrappedToken]; ok && cached.Expires.After(time.Now()) && cached.UserID == userID {
		return nil
	} else if validationResult, err := prov.fedClient.GetOpenIDUserInfo(ctx, homeserver, token); err != nil {
		return fmt.Errorf("failed to validate OpenID token: %w", err)
	} else if validationResult.Sub != userID {
		return fmt.Errorf("mismatching user ID (%q != %q)", validationResult, userID)
	} else {
		prov.matrixAuthCache[wrappedToken] = matrixAuthCacheEntry{
			Expires: time.Now().Add(1 * time.Hour),
			UserID:  userID,
		}
		return nil
	}
}

func (prov *ProvisioningAPI) AuthMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if auth == "" {
			jsonResponse(w, http.StatusUnauthorized, &mautrix.RespError{
				Err:     "Missing auth token",
				ErrCode: mautrix.MMissingToken.ErrCode,
			})
			return
		}
		userID := id.UserID(r.URL.Query().Get("user_id"))
		if auth != prov.br.Config.Provisioning.SharedSecret {
			var err error
			if strings.HasPrefix(auth, "openid:") {
				err = prov.checkFederatedMatrixAuth(r.Context(), userID, strings.TrimPrefix(auth, "openid:"))
			} else {
				err = prov.checkMatrixAuth(r.Context(), userID, auth)
			}
			if err != nil {
				zerolog.Ctx(r.Context()).Warn().Err(err).
					Msg("Provisioning API request contained invalid auth")
				jsonResponse(w, http.StatusUnauthorized, &mautrix.RespError{
					Err:     "Invalid auth token",
					ErrCode: mautrix.MUnknownToken.ErrCode,
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

type RespWhoami struct {
	Network       bridgev2.BridgeName  `json:"network"`
	LoginFlows    []bridgev2.LoginFlow `json:"login_flows"`
	Homeserver    string               `json:"homeserver"`
	BridgeBot     id.UserID            `json:"bridge_bot"`
	CommandPrefix string               `json:"command_prefix"`

	ManagementRoom id.RoomID         `json:"management_room"`
	Logins         []RespWhoamiLogin `json:"logins"`
}

type RespWhoamiLogin struct {
	StateEvent  status.BridgeStateEvent `json:"state_event"`
	StateTS     jsontime.Unix           `json:"state_ts"`
	StateReason string                  `json:"state_reason,omitempty"`
	StateInfo   map[string]any          `json:"state_info,omitempty"`
	ID          networkid.UserLoginID   `json:"id"`
	Name        string                  `json:"name"`
	Profile     status.RemoteProfile    `json:"profile"`
	SpaceRoom   id.RoomID               `json:"space_room"`
}

func (prov *ProvisioningAPI) GetWhoami(w http.ResponseWriter, r *http.Request) {
	user := prov.GetUser(r)
	resp := &RespWhoami{
		Network:        prov.br.Bridge.Network.GetName(),
		LoginFlows:     prov.br.Bridge.Network.GetLoginFlows(),
		Homeserver:     prov.br.AS.HomeserverDomain,
		BridgeBot:      prov.br.Bot.UserID,
		CommandPrefix:  prov.br.Config.Bridge.CommandPrefix,
		ManagementRoom: user.ManagementRoom,
	}
	logins := user.GetCachedUserLogins()
	resp.Logins = make([]RespWhoamiLogin, len(logins))
	for i, login := range logins {
		prevState := login.BridgeState.GetPrevUnsent()
		resp.Logins[i] = RespWhoamiLogin{
			StateEvent:  prevState.StateEvent,
			StateTS:     prevState.Timestamp,
			StateReason: prevState.Reason,
			StateInfo:   prevState.Info,

			ID:        login.ID,
			Name:      login.RemoteName,
			Profile:   login.RemoteProfile,
			SpaceRoom: login.SpaceRoom,
		}
	}
	jsonResponse(w, http.StatusOK, resp)
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
	overrideLogin, failed := prov.GetExplicitLoginForRequest(w, r)
	if failed {
		return
	}
	login, err := prov.net.CreateLogin(
		r.Context(),
		prov.GetUser(r),
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
		Override: overrideLogin,
	}
	prov.loginsLock.Unlock()
	jsonResponse(w, http.StatusOK, &RespSubmitLogin{LoginID: loginID, LoginStep: firstStep})
}

func (prov *ProvisioningAPI) handleCompleteStep(ctx context.Context, login *ProvLogin, step *bridgev2.LoginStep) {
	if login.Override == nil || login.Override.ID == step.CompleteParams.UserLoginID {
		return
	}
	zerolog.Ctx(ctx).Info().
		Str("old_login_id", string(login.Override.ID)).
		Str("new_login_id", string(step.CompleteParams.UserLoginID)).
		Msg("Login resulted in different remote ID than what was being overridden. Deleting previous login")
	login.Override.Delete(ctx, status.BridgeState{
		StateEvent: status.StateLoggedOut,
		Reason:     "LOGIN_OVERRIDDEN",
	}, true)
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
	if nextStep.Type == bridgev2.LoginStepTypeComplete {
		prov.handleCompleteStep(r.Context(), login, nextStep)
	}
	jsonResponse(w, http.StatusOK, &RespSubmitLogin{LoginID: login.ID, LoginStep: nextStep})
}

func (prov *ProvisioningAPI) PostLoginWait(w http.ResponseWriter, r *http.Request) {
	login := r.Context().Value(provisioningLoginProcessKey).(*ProvLogin)
	nextStep, err := login.Process.(bridgev2.LoginProcessDisplayAndWait).Wait(r.Context())
	if err != nil {
		zerolog.Ctx(r.Context()).Err(err).Msg("Failed to wait")
		jsonResponse(w, http.StatusInternalServerError, &mautrix.RespError{
			Err:     "Failed to wait",
			ErrCode: "M_UNKNOWN",
		})
		return
	}
	login.NextStep = nextStep
	if nextStep.Type == bridgev2.LoginStepTypeComplete {
		prov.handleCompleteStep(r.Context(), login, nextStep)
	}
	jsonResponse(w, http.StatusOK, &RespSubmitLogin{LoginID: login.ID, LoginStep: nextStep})
}

func (prov *ProvisioningAPI) PostLogout(w http.ResponseWriter, r *http.Request) {
	user := prov.GetUser(r)
	userLoginID := networkid.UserLoginID(mux.Vars(r)["loginID"])
	if userLoginID == "all" {
		for {
			login := user.GetDefaultLogin()
			if login == nil {
				break
			}
			login.Logout(r.Context())
		}
	} else {
		userLogin := prov.br.Bridge.GetCachedUserLoginByID(userLoginID)
		if userLogin == nil || userLogin.UserMXID != user.MXID {
			jsonResponse(w, http.StatusNotFound, &mautrix.RespError{
				Err:     "Login not found",
				ErrCode: mautrix.MNotFound.ErrCode,
			})
			return
		}
		userLogin.Logout(r.Context())
	}
	jsonResponse(w, http.StatusOK, json.RawMessage("{}"))
}

type RespGetLogins struct {
	LoginIDs []networkid.UserLoginID `json:"login_ids"`
}

func (prov *ProvisioningAPI) GetLogins(w http.ResponseWriter, r *http.Request) {
	user := prov.GetUser(r)
	jsonResponse(w, http.StatusOK, &RespGetLogins{LoginIDs: user.GetUserLoginIDs()})
}

func (prov *ProvisioningAPI) GetExplicitLoginForRequest(w http.ResponseWriter, r *http.Request) (*bridgev2.UserLogin, bool) {
	userLoginID := networkid.UserLoginID(r.URL.Query().Get("login_id"))
	if userLoginID == "" {
		return nil, false
	}
	userLogin := prov.br.Bridge.GetCachedUserLoginByID(userLoginID)
	if userLogin == nil || userLogin.UserMXID != prov.GetUser(r).MXID {
		jsonResponse(w, http.StatusNotFound, &mautrix.RespError{
			Err:     "Login not found",
			ErrCode: mautrix.MNotFound.ErrCode,
		})
		return nil, true
	}
	return userLogin, false
}

func (prov *ProvisioningAPI) GetLoginForRequest(w http.ResponseWriter, r *http.Request) *bridgev2.UserLogin {
	userLogin, failed := prov.GetExplicitLoginForRequest(w, r)
	if userLogin != nil || failed {
		return userLogin
	}
	userLogin = prov.GetUser(r).GetDefaultLogin()
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
	ID          networkid.UserID    `json:"id"`
	Name        string              `json:"name,omitempty"`
	AvatarURL   id.ContentURIString `json:"avatar_url,omitempty"`
	Identifiers []string            `json:"identifiers,omitempty"`
	MXID        id.UserID           `json:"mxid,omitempty"`
	DMRoomID    id.RoomID           `json:"dm_room_mxid,omitempty"`
}

func (prov *ProvisioningAPI) doResolveIdentifier(w http.ResponseWriter, r *http.Request, createChat bool) {
	login := prov.GetLoginForRequest(w, r)
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
		jsonResponse(w, http.StatusInternalServerError, &mautrix.RespError{
			Err:     fmt.Sprintf("Failed to resolve identifier: %v", err),
			ErrCode: "M_UNKNOWN",
		})
		return
	} else if resp == nil {
		jsonResponse(w, http.StatusNotFound, &mautrix.RespError{
			ErrCode: mautrix.MNotFound.ErrCode,
			Err:     "Identifier not found",
		})
		return
	}
	apiResp := &RespResolveIdentifier{
		ID: resp.UserID,
	}
	status := http.StatusOK
	if resp.Ghost != nil {
		if resp.UserInfo != nil {
			resp.Ghost.UpdateInfo(r.Context(), resp.UserInfo)
		}
		apiResp.Name = resp.Ghost.Name
		apiResp.AvatarURL = resp.Ghost.AvatarMXC
		apiResp.Identifiers = resp.Ghost.Identifiers
		apiResp.MXID = resp.Ghost.Intent.GetMXID()
	} else if resp.UserInfo != nil && resp.UserInfo.Name != nil {
		apiResp.Name = *resp.UserInfo.Name
	}
	if resp.Chat != nil {
		if resp.Chat.Portal == nil {
			resp.Chat.Portal, err = prov.br.Bridge.GetPortalByKey(r.Context(), resp.Chat.PortalKey)
			if err != nil {
				zerolog.Ctx(r.Context()).Err(err).Msg("Failed to get portal")
				jsonResponse(w, http.StatusInternalServerError, &mautrix.RespError{
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
				jsonResponse(w, http.StatusInternalServerError, &mautrix.RespError{
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

type RespGetContactList struct {
	Contacts []*RespResolveIdentifier `json:"contacts"`
}

func (prov *ProvisioningAPI) GetContactList(w http.ResponseWriter, r *http.Request) {
	login := prov.GetLoginForRequest(w, r)
	if login == nil {
		return
	}
	api, ok := login.Client.(bridgev2.ContactListingNetworkAPI)
	if !ok {
		jsonResponse(w, http.StatusNotImplemented, &mautrix.RespError{
			Err:     "This bridge does not support listing contacts",
			ErrCode: mautrix.MUnrecognized.ErrCode,
		})
		return
	}
	resp, err := api.GetContactList(r.Context())
	if err != nil {
		zerolog.Ctx(r.Context()).Err(err).Msg("Failed to get contact list")
		jsonResponse(w, http.StatusNotImplemented, &mautrix.RespError{
			Err:     fmt.Sprintf("Failed to get contact list: %v", err),
			ErrCode: "M_UNKNOWN",
		})
		return
	}
	apiResp := &RespGetContactList{
		Contacts: make([]*RespResolveIdentifier, len(resp)),
	}
	for i, contact := range resp {
		apiContact := &RespResolveIdentifier{
			ID: contact.UserID,
		}
		fmt.Println(contact.UserInfo.Identifiers)
		apiResp.Contacts[i] = apiContact
		if contact.UserInfo != nil {
			if contact.UserInfo.Name != nil {
				apiContact.Name = *contact.UserInfo.Name
			}
			if contact.UserInfo.Identifiers != nil {
				apiContact.Identifiers = contact.UserInfo.Identifiers
			}
		}
		if contact.Ghost != nil {
			if contact.Ghost.Name != "" {
				apiContact.Name = contact.Ghost.Name
			}
			if len(contact.Ghost.Identifiers) >= len(apiContact.Identifiers) {
				apiContact.Identifiers = contact.Ghost.Identifiers
			}
			apiContact.AvatarURL = contact.Ghost.AvatarMXC
			apiContact.MXID = contact.Ghost.Intent.GetMXID()
		}
		if contact.Chat != nil {
			if contact.Chat.Portal == nil {
				contact.Chat.Portal, err = prov.br.Bridge.GetPortalByKey(r.Context(), contact.Chat.PortalKey)
				if err != nil {
					zerolog.Ctx(r.Context()).Err(err).Msg("Failed to get portal")
					jsonResponse(w, http.StatusInternalServerError, &mautrix.RespError{
						Err:     "Failed to get portal",
						ErrCode: "M_UNKNOWN",
					})
					return
				}
			}
			apiContact.DMRoomID = contact.Chat.Portal.MXID
		}
	}
	jsonResponse(w, http.StatusOK, apiResp)
}

func (prov *ProvisioningAPI) GetResolveIdentifier(w http.ResponseWriter, r *http.Request) {
	prov.doResolveIdentifier(w, r, false)
}

func (prov *ProvisioningAPI) PostCreateDM(w http.ResponseWriter, r *http.Request) {
	prov.doResolveIdentifier(w, r, true)
}

func (prov *ProvisioningAPI) PostCreateGroup(w http.ResponseWriter, r *http.Request) {
	login := prov.GetLoginForRequest(w, r)
	if login == nil {
		return
	}
	jsonResponse(w, http.StatusNotImplemented, &mautrix.RespError{
		Err:     "Creating groups is not yet implemented",
		ErrCode: mautrix.MUnrecognized.ErrCode,
	})
}
