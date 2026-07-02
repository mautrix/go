// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"go.mau.fi/util/exerrors"
	"go.mau.fi/util/exhttp"
	"go.mau.fi/util/exstrings"
	"go.mau.fi/util/jsontime"
	"go.mau.fi/util/ptr"
	"go.mau.fi/util/requestlog"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/provisionutil"
	"maunium.net/go/mautrix/bridgev2/status"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"
)

type matrixAuthCacheEntry struct {
	Expires time.Time
	UserID  id.UserID
}

type ProvisioningAPI struct {
	Router *http.ServeMux

	br  *Connector
	log zerolog.Logger
	net bridgev2.NetworkConnector

	fedClient *federation.Client

	logins     map[string]*ProvLogin
	loginsLock sync.RWMutex

	matrixAuthCache     map[string]matrixAuthCacheEntry
	matrixAuthCacheLock sync.Mutex

	// Set for a given login once credentials have been exported, once in this state the finish
	// API is available which will call logout on the client in question.
	sessionTransfers     map[networkid.UserLoginID]struct{}
	sessionTransfersLock sync.Mutex

	// GetAuthFromRequest is a custom function for getting the auth token from
	// the request if the Authorization header is not present.
	GetAuthFromRequest func(r *http.Request) string

	// GetUserIDFromRequest is a custom function for getting the user ID to
	// authenticate as instead of using the user ID provided in the query
	// parameter.
	GetUserIDFromRequest func(r *http.Request) id.UserID
}

type provisioningContextKey int

const (
	provisioningUserKey provisioningContextKey = iota
	ProvisioningKeyRequest
)

func (prov *ProvisioningAPI) GetUser(r *http.Request) *bridgev2.User {
	return r.Context().Value(provisioningUserKey).(*bridgev2.User)
}

func (prov *ProvisioningAPI) GetRouter() *http.ServeMux {
	return prov.Router
}

func (br *Connector) GetProvisioning() bridgev2.IProvisioningAPI {
	return br.Provisioning
}

func (prov *ProvisioningAPI) Init() {
	prov.matrixAuthCache = make(map[string]matrixAuthCacheEntry)
	prov.logins = make(map[string]*ProvLogin)
	prov.sessionTransfers = make(map[networkid.UserLoginID]struct{})
	prov.net = prov.br.Bridge.Network
	prov.log = prov.br.Log.With().Str("component", "provisioning").Logger()
	prov.fedClient = federation.NewClient("", nil, nil, exhttp.SensibleClientSettings.WithGlobalTimeout(20*time.Second))
	prov.Router = http.NewServeMux()
	prov.Router.HandleFunc("GET /v3/whoami", prov.GetWhoami)
	prov.Router.HandleFunc("GET /v3/capabilities", prov.GetCapabilities)
	prov.Router.HandleFunc("GET /v3/login/flows", prov.GetLoginFlows)
	prov.Router.HandleFunc("POST /v3/login/start/{flowID}", prov.PostLoginStart)
	prov.Router.HandleFunc("POST /v3/login/step/{loginProcessID}/{stepID}/{stepType}", prov.PostLoginStep)
	prov.Router.HandleFunc("POST /v3/login/cancel/{loginProcessID}", prov.PostLoginCancel)
	prov.Router.HandleFunc("POST /v3/logout/{loginID}", prov.PostLogout)
	prov.Router.HandleFunc("GET /v3/logins", prov.GetLogins)
	prov.Router.HandleFunc("GET /v3/contacts", prov.GetContactList)
	prov.Router.HandleFunc("POST /v3/search_users", prov.PostSearchUsers)
	prov.Router.HandleFunc("GET /v3/resolve_identifier/{identifier}", prov.GetResolveIdentifier)
	prov.Router.HandleFunc("POST /v3/create_dm/{identifier}", prov.PostCreateDM)
	prov.Router.HandleFunc("POST /v3/create_group/{type}", prov.PostCreateGroup)
	prov.Router.HandleFunc("POST /v3/backfill/{roomID}", prov.PostPaginate)
	prov.Router.HandleFunc("GET /v3/image_pack/import", prov.ImportImagePack)
	prov.Router.HandleFunc("POST /v3/image_pack/import", prov.ImportImagePack)
	prov.Router.HandleFunc("GET /v3/image_pack/list", prov.ListImagePacks)

	if prov.br.Config.Provisioning.EnableSessionTransfers {
		prov.log.Debug().Msg("Enabling session transfer API")
		prov.Router.HandleFunc("POST /v3/session_transfer/init", prov.PostInitSessionTransfer)
		prov.Router.HandleFunc("POST /v3/session_transfer/finish", prov.PostFinishSessionTransfer)
	}

	if prov.br.Config.Provisioning.DebugEndpoints {
		prov.log.Debug().Msg("Enabling debug API at /debug")
		debugRouter := http.NewServeMux()
		debugRouter.HandleFunc("GET /pprof/cmdline", pprof.Cmdline)
		debugRouter.HandleFunc("GET /pprof/profile", pprof.Profile)
		debugRouter.HandleFunc("GET /pprof/symbol", pprof.Symbol)
		debugRouter.HandleFunc("GET /pprof/trace", pprof.Trace)
		debugRouter.HandleFunc("/pprof/", pprof.Index)
		prov.br.AS.Router.Handle("/debug/", exhttp.ApplyMiddleware(
			debugRouter,
			exhttp.StripPrefix("/debug"),
			hlog.NewHandler(prov.br.Log.With().Str("component", "debug api").Logger()),
			requestlog.AccessLogger(requestlog.Options{TrustXForwardedFor: true}),
			prov.DebugAuthMiddleware,
		))
	}

	errorBodies := exhttp.ErrorBodies{
		NotFound:         exerrors.Must(ptr.Ptr(mautrix.MUnrecognized.WithMessage("Unrecognized endpoint")).MarshalJSON()),
		MethodNotAllowed: exerrors.Must(ptr.Ptr(mautrix.MUnrecognized.WithMessage("Invalid method for endpoint")).MarshalJSON()),
	}
	prov.br.AS.Router.Handle("/_matrix/provision/", exhttp.ApplyMiddleware(
		prov.Router,
		exhttp.StripPrefix("/_matrix/provision"),
		hlog.NewHandler(prov.log),
		hlog.RequestIDHandler("request_id", "Request-Id"),
		exhttp.CORSMiddleware,
		requestlog.AccessLogger(requestlog.Options{TrustXForwardedFor: true}),
		exhttp.HandleErrors(errorBodies),
		prov.AuthMiddleware,
	))
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

func disabledAuth(w http.ResponseWriter, r *http.Request) {
	mautrix.MForbidden.WithMessage("Provisioning API is disabled").Write(w)
}

func (prov *ProvisioningAPI) DebugAuthMiddleware(h http.Handler) http.Handler {
	secret := prov.br.Config.Provisioning.SharedSecret
	if len(secret) < 16 {
		return http.HandlerFunc(disabledAuth)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if auth == "" {
			mautrix.MMissingToken.WithMessage("Missing auth token").Write(w)
		} else if !exstrings.ConstantTimeEqual(auth, secret) {
			mautrix.MUnknownToken.WithMessage("Invalid auth token").Write(w)
		} else {
			h.ServeHTTP(w, r)
		}
	})
}

func (prov *ProvisioningAPI) AuthMiddleware(h http.Handler) http.Handler {
	secret := prov.br.Config.Provisioning.SharedSecret
	if len(secret) < 16 {
		return http.HandlerFunc(disabledAuth)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if auth == "" && prov.GetAuthFromRequest != nil {
			auth = prov.GetAuthFromRequest(r)
		}
		if auth == "" {
			mautrix.MMissingToken.WithMessage("Missing auth token").Write(w)
			return
		}
		userID := id.UserID(r.URL.Query().Get("user_id"))
		if userID == "" && prov.GetUserIDFromRequest != nil {
			userID = prov.GetUserIDFromRequest(r)
		}
		if !exstrings.ConstantTimeEqual(auth, secret) {
			var err error
			if !prov.br.Config.Provisioning.AllowMatrixAuth {
				err = errors.New("matrix auth is disabled")
			} else if strings.HasPrefix(auth, "openid:") {
				err = prov.checkFederatedMatrixAuth(r.Context(), userID, strings.TrimPrefix(auth, "openid:"))
			} else {
				err = prov.checkMatrixAuth(r.Context(), userID, auth)
			}
			if err != nil {
				zerolog.Ctx(r.Context()).Warn().Err(err).
					Msg("Provisioning API request contained invalid auth")
				mautrix.MUnknownToken.WithMessage("Invalid auth token").Write(w)
				return
			}
		}
		user, err := prov.br.Bridge.GetUserByMXID(r.Context(), userID)
		if err != nil {
			zerolog.Ctx(r.Context()).Err(err).Msg("Failed to get user")
			mautrix.MUnknown.WithMessage("Failed to get user").Write(w)
			return
		}
		// TODO handle user being nil?
		// TODO per-endpoint permissions?
		if !user.Permissions.Login {
			mautrix.MForbidden.WithMessage("User does not have login permissions").Write(w)
			return
		}

		ctx := context.WithValue(r.Context(), ProvisioningKeyRequest, r)
		ctx = context.WithValue(ctx, provisioningUserKey, user)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

type RespWhoami struct {
	Network       bridgev2.BridgeName  `json:"network"`
	LoginFlows    []bridgev2.LoginFlow `json:"login_flows"`
	Homeserver    string               `json:"homeserver"`
	BridgeBot     id.UserID            `json:"bridge_bot"`
	CommandPrefix string               `json:"command_prefix"`

	ManagementRoom id.RoomID         `json:"management_room,omitempty"`
	Logins         []RespWhoamiLogin `json:"logins"`
}

type RespWhoamiLogin struct {
	// Deprecated
	StateEvent status.BridgeStateEvent `json:"state_event"`
	// Deprecated
	StateTS jsontime.Unix `json:"state_ts"`
	// Deprecated
	StateReason string `json:"state_reason,omitempty"`
	// Deprecated
	StateInfo map[string]any `json:"state_info,omitempty"`

	State     status.BridgeState    `json:"state"`
	ID        networkid.UserLoginID `json:"id"`
	Name      string                `json:"name"`
	Profile   status.RemoteProfile  `json:"profile"`
	SpaceRoom id.RoomID             `json:"space_room,omitempty"`
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
	logins := user.GetUserLogins()
	resp.Logins = make([]RespWhoamiLogin, len(logins))
	for i, login := range logins {
		prevState := login.BridgeState.GetPrevUnsent()
		// Clear redundant fields
		prevState.UserID = ""
		prevState.RemoteID = ""
		prevState.RemoteName = ""
		prevState.RemoteProfile = status.RemoteProfile{}
		resp.Logins[i] = RespWhoamiLogin{
			StateEvent:  prevState.StateEvent,
			StateTS:     prevState.Timestamp,
			StateReason: prevState.Reason,
			StateInfo:   prevState.Info,
			State:       prevState,

			ID:        login.ID,
			Name:      login.RemoteName,
			Profile:   login.RemoteProfile,
			SpaceRoom: login.SpaceRoom,
		}
	}
	exhttp.WriteJSONResponse(w, http.StatusOK, resp)
}

type RespLoginFlows struct {
	Flows []bridgev2.LoginFlow `json:"flows"`
}

type RespSubmitLogin struct {
	LoginID string `json:"login_id"`
	*bridgev2.LoginStep
}

func (prov *ProvisioningAPI) GetLoginFlows(w http.ResponseWriter, r *http.Request) {
	exhttp.WriteJSONResponse(w, http.StatusOK, &RespLoginFlows{
		Flows: prov.net.GetLoginFlows(),
	})
}

func (prov *ProvisioningAPI) GetCapabilities(w http.ResponseWriter, r *http.Request) {
	exhttp.WriteJSONResponse(w, http.StatusOK, &prov.net.GetCapabilities().Provisioning)
}

func (prov *ProvisioningAPI) PostLogout(w http.ResponseWriter, r *http.Request) {
	user := prov.GetUser(r)
	userLoginID := networkid.UserLoginID(r.PathValue("loginID"))
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
			mautrix.MNotFound.WithMessage("Login not found").Write(w)
			return
		}
		userLogin.Logout(r.Context())
	}
	exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
}

type RespGetLogins struct {
	LoginIDs []networkid.UserLoginID `json:"login_ids"`
}

func (prov *ProvisioningAPI) GetLogins(w http.ResponseWriter, r *http.Request) {
	user := prov.GetUser(r)
	exhttp.WriteJSONResponse(w, http.StatusOK, &RespGetLogins{LoginIDs: user.GetUserLoginIDs()})
}

func (prov *ProvisioningAPI) GetExplicitLoginForRequest(w http.ResponseWriter, r *http.Request) (*bridgev2.UserLogin, bool) {
	userLoginID := networkid.UserLoginID(r.URL.Query().Get("login_id"))
	if userLoginID == "" {
		return nil, false
	}
	userLogin := prov.br.Bridge.GetCachedUserLoginByID(userLoginID)
	if userLogin == nil || userLogin.UserMXID != prov.GetUser(r).MXID {
		hlog.FromRequest(r).Warn().
			Str("login_id", string(userLoginID)).
			Msg("Tried to use non-existent login, returning 404")
		mautrix.MNotFound.WithMessage("Login not found").Write(w)
		return nil, true
	}
	return userLogin, false
}

var ErrNotLoggedIn = mautrix.RespError{
	Err:        "Not logged in",
	ErrCode:    "FI.MAU.NOT_LOGGED_IN",
	StatusCode: http.StatusBadRequest,
}

func (prov *ProvisioningAPI) GetLoginForRequest(w http.ResponseWriter, r *http.Request) *bridgev2.UserLogin {
	userLogin, failed := prov.GetExplicitLoginForRequest(w, r)
	if userLogin != nil || failed {
		return userLogin
	}
	userLogin = prov.GetUser(r).GetDefaultLogin()
	if userLogin == nil {
		ErrNotLoggedIn.Write(w)
		return nil
	}
	return userLogin
}

type WritableError interface {
	Write(w http.ResponseWriter)
}

func RespondWithError(w http.ResponseWriter, err error, message string) {
	var we WritableError
	if errors.As(err, &we) {
		we.Write(w)
	} else {
		mautrix.MUnknown.WithMessage(message).WithInternalError(err).Write(w)
	}
}

func (prov *ProvisioningAPI) doResolveIdentifier(w http.ResponseWriter, r *http.Request, createChat bool) {
	login := prov.GetLoginForRequest(w, r)
	if login == nil {
		return
	}
	resp, err := provisionutil.ResolveIdentifier(r.Context(), login, r.PathValue("identifier"), createChat)
	if err != nil {
		RespondWithError(w, err, "Internal error resolving identifier")
	} else if resp == nil {
		mautrix.MNotFound.WithMessage("Identifier not found").Write(w)
	} else {
		status := http.StatusOK
		if resp.JustCreated {
			status = http.StatusCreated
		}
		exhttp.WriteJSONResponse(w, status, resp)
	}
}

func (prov *ProvisioningAPI) GetContactList(w http.ResponseWriter, r *http.Request) {
	login := prov.GetLoginForRequest(w, r)
	if login == nil {
		return
	}
	resp, err := provisionutil.GetContactList(r.Context(), login)
	if err != nil {
		RespondWithError(w, err, "Internal error getting contact list")
		return
	}
	exhttp.WriteJSONResponse(w, http.StatusOK, resp)
}

type ReqSearchUsers struct {
	Query string `json:"query"`
}

func (prov *ProvisioningAPI) PostSearchUsers(w http.ResponseWriter, r *http.Request) {
	var req ReqSearchUsers
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		zerolog.Ctx(r.Context()).Err(err).Msg("Failed to decode request body")
		mautrix.MNotJSON.WithMessage("Failed to decode request body").Write(w)
		return
	}
	login := prov.GetLoginForRequest(w, r)
	if login == nil {
		return
	}
	resp, err := provisionutil.SearchUsers(r.Context(), login, req.Query)
	if err != nil {
		RespondWithError(w, err, "Internal error searching users")
		return
	}
	exhttp.WriteJSONResponse(w, http.StatusOK, resp)
}

func (prov *ProvisioningAPI) GetResolveIdentifier(w http.ResponseWriter, r *http.Request) {
	prov.doResolveIdentifier(w, r, false)
}

func (prov *ProvisioningAPI) PostCreateDM(w http.ResponseWriter, r *http.Request) {
	prov.doResolveIdentifier(w, r, true)
}

func (prov *ProvisioningAPI) PostCreateGroup(w http.ResponseWriter, r *http.Request) {
	var req bridgev2.GroupCreateParams
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		zerolog.Ctx(r.Context()).Err(err).Msg("Failed to decode request body")
		mautrix.MNotJSON.WithMessage("Failed to decode request body").Write(w)
		return
	}
	req.Type = r.PathValue("type")
	login := prov.GetLoginForRequest(w, r)
	if login == nil {
		return
	}
	resp, err := provisionutil.CreateGroup(r.Context(), login, &req)
	if err != nil {
		RespondWithError(w, err, "Internal error creating group")
		return
	}
	exhttp.WriteJSONResponse(w, http.StatusOK, resp)
}

func (prov *ProvisioningAPI) PostPaginate(w http.ResponseWriter, r *http.Request) {
	if !prov.br.Capabilities.BatchSending {
		mautrix.MUnrecognized.WithMessage("Homeserver does not support batch sending historical messages").Write(w)
		return
	} else if !prov.br.Config.Backfill.Queue.Manual {
		mautrix.MUnrecognized.WithMessage("Manual backfill is not enabled").Write(w)
		return
	}
	log := zerolog.Ctx(r.Context())
	login := prov.GetLoginForRequest(w, r)
	if login == nil {
		return
	}
	targetRoomID := id.RoomID(r.PathValue("roomID"))
	portal, err := prov.br.Bridge.GetPortalByMXID(r.Context(), targetRoomID)
	if err != nil {
		log.Err(err).Msg("Failed to get portal for pagination")
		RespondWithError(w, err, "Internal error getting portal")
	} else if portal == nil {
		log.Debug().Stringer("target_room_id", targetRoomID).Msg("Paginate requested for unknown portal room")
		mautrix.MNotFound.WithMessage("Portal not found").Write(w)
	} else if task, err := prov.br.Bridge.DB.BackfillTask.GetNextForPortal(r.Context(), portal.PortalKey, false); err != nil {
		log.Err(err).Msg("Failed to get backfill task for portal")
		RespondWithError(w, err, "Internal error getting backfill task")
	} else if task == nil {
		log.Debug().Msg("No backfill task found for portal")
		w.WriteHeader(http.StatusNoContent)
	} else {
		log.Info().
			Object("portal_key", portal.PortalKey).
			Any("current_backfill_task", task).
			Msg("Sending manual backfill request to backfill queue")
		doneChan := make(chan error, 1)
		var done atomic.Bool
		prov.br.Bridge.WakeupBackfillQueue(&bridgev2.ManualBackfill{
			Source: login,
			Portal: portal,
			DoneCallback: func(err error) {
				if done.Swap(true) {
					log.Warn().Err(err).Msg("Backfill done callback called multiple times, ignoring")
					return
				}
				log.Debug().Msg("Backfill done callback called, sending result to channel")
				doneChan <- err
				close(doneChan)
			},
		})
		select {
		case err = <-doneChan:
			if err != nil {
				RespondWithError(w, err, "Internal error backfilling")
			} else {
				exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
			}
		case <-time.After(25 * time.Second):
			log.Warn().Msg("Backfill did not complete within 25 seconds, returning timeout")
			mautrix.MUnknown.WithMessage("Backfill did not complete within 25 seconds").Write(w)
		case <-r.Context().Done():
			log.Warn().Msg("Request cancelled while waiting for backfill to complete")
		}
	}
}

func (prov *ProvisioningAPI) ImportImagePack(w http.ResponseWriter, r *http.Request) {
	login := prov.GetLoginForRequest(w, r)
	if login == nil {
		return
	}
	var resp any
	var err error
	if r.Method == http.MethodPost {
		resp, err = provisionutil.ImportImagePack(r.Context(), login, r.URL.Query().Get("pack_url"))
	} else {
		resp, err = provisionutil.PreviewImagePack(r.Context(), login, r.URL.Query().Get("pack_url"))
	}
	if err != nil {
		RespondWithError(w, err, "Internal error importing image pack")
		return
	}
	exhttp.WriteJSONResponse(w, http.StatusOK, resp)
}

func (prov *ProvisioningAPI) ListImagePacks(w http.ResponseWriter, r *http.Request) {
	login := prov.GetLoginForRequest(w, r)
	if login == nil {
		return
	}
	resp, err := provisionutil.ListImagePacks(r.Context(), login)
	if err != nil {
		RespondWithError(w, err, "Internal error listing image packs")
		return
	}
	exhttp.WriteJSONResponse(w, http.StatusOK, resp)
}

type ReqExportCredentials struct {
	RemoteID networkid.UserLoginID `json:"remote_id"`
}

type RespExportCredentials struct {
	Credentials any `json:"credentials"`
}

func (prov *ProvisioningAPI) PostInitSessionTransfer(w http.ResponseWriter, r *http.Request) {
	prov.sessionTransfersLock.Lock()
	defer prov.sessionTransfersLock.Unlock()

	var req ReqExportCredentials
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		zerolog.Ctx(r.Context()).Err(err).Msg("Failed to decode request body")
		mautrix.MNotJSON.WithMessage("Failed to decode request body").Write(w)
		return
	}

	user := prov.GetUser(r)
	logins := user.GetUserLogins()
	var loginToExport *bridgev2.UserLogin
	for _, login := range logins {
		if login.ID == req.RemoteID {
			loginToExport = login
			break
		}
	}
	if loginToExport == nil {
		mautrix.MNotFound.WithMessage("No matching user login found").Write(w)
		return
	}

	client, ok := loginToExport.Client.(bridgev2.CredentialExportingNetworkAPI)
	if !ok {
		mautrix.MUnrecognized.WithMessage("This bridge does not support exporting credentials").Write(w)
		return
	}

	if _, ok := prov.sessionTransfers[loginToExport.ID]; ok {
		// Warn, but allow, double exports. This might happen if a client crashes handling creds,
		// and should be safe to call multiple times.
		zerolog.Ctx(r.Context()).Warn().Msg("Exporting already exported credentials")
	}

	// Disconnect now so we don't use the same network session in two places at once
	client.Disconnect()
	exhttp.WriteJSONResponse(w, http.StatusOK, &RespExportCredentials{
		Credentials: client.ExportCredentials(r.Context()),
	})
}

func (prov *ProvisioningAPI) PostFinishSessionTransfer(w http.ResponseWriter, r *http.Request) {
	prov.sessionTransfersLock.Lock()
	defer prov.sessionTransfersLock.Unlock()

	var req ReqExportCredentials
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		zerolog.Ctx(r.Context()).Err(err).Msg("Failed to decode request body")
		mautrix.MNotJSON.WithMessage("Failed to decode request body").Write(w)
		return
	}

	user := prov.GetUser(r)
	logins := user.GetUserLogins()
	var loginToExport *bridgev2.UserLogin
	for _, login := range logins {
		if login.ID == req.RemoteID {
			loginToExport = login
			break
		}
	}
	if loginToExport == nil {
		mautrix.MNotFound.WithMessage("No matching user login found").Write(w)
		return
	} else if _, ok := prov.sessionTransfers[loginToExport.ID]; !ok {
		mautrix.MBadState.WithMessage("No matching credential export found").Write(w)
		return
	}

	zerolog.Ctx(r.Context()).Info().
		Str("remote_name", string(req.RemoteID)).
		Msg("Logging out remote after finishing credential export")

	loginToExport.Client.LogoutRemote(r.Context())
	delete(prov.sessionTransfers, req.RemoteID)

	exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
}
