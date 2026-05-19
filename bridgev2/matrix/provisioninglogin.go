// Copyright (c) 2026 Tulir Asokan
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
	"sync"
	"time"

	"github.com/rs/xid"
	"github.com/rs/zerolog"
	"go.mau.fi/util/exhttp"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/status"
)

type ProvLogin struct {
	ID       string
	Process  bridgev2.LoginProcess
	PrevStep *bridgev2.LoginStep
	NextStep *bridgev2.LoginStep
	Override *bridgev2.UserLogin
	Lock     sync.Mutex

	Ctx       context.Context
	CancelCtx context.CancelFunc
}

var ErrNilStep = errors.New("bridge returned nil step with no error")
var ErrTooManyLogins = bridgev2.RespError{ErrCode: "FI.MAU.BRIDGE.TOO_MANY_LOGINS", Err: "Maximum number of logins exceeded"}

func (prov *ProvisioningAPI) PostLoginStart(w http.ResponseWriter, r *http.Request) {
	overrideLogin, failed := prov.GetExplicitLoginForRequest(w, r)
	if failed {
		return
	}
	user := prov.GetUser(r)
	if overrideLogin == nil && user.HasTooManyLogins() {
		ErrTooManyLogins.AppendMessage(" (%d)", user.Permissions.MaxLogins).Write(w)
		return
	}
	login, err := prov.net.CreateLogin(r.Context(), user, r.PathValue("flowID"))
	if err != nil {
		zerolog.Ctx(r.Context()).Err(err).Msg("Failed to create login process")
		RespondWithError(w, err, "Internal error creating login process")
		return
	}
	var firstStep *bridgev2.LoginStep
	overridable, ok := login.(bridgev2.LoginProcessWithOverride)
	if ok && overrideLogin != nil {
		firstStep, err = overridable.StartWithOverride(r.Context(), overrideLogin)
	} else {
		firstStep, err = login.Start(r.Context())
	}
	if err == nil && firstStep == nil {
		err = ErrNilStep
	}
	if err != nil {
		zerolog.Ctx(r.Context()).Err(err).Msg("Failed to start login")
		RespondWithError(w, err, "Internal error starting login")
		return
	}
	loginID := xid.New().String()
	ctx, cancel := context.WithTimeout(prov.br.Bridge.BackgroundCtx, 15*time.Minute)
	ctx = user.Log.With().
		Str("login_id", loginID).
		Logger().WithContext(ctx)
	provLogin := &ProvLogin{
		ID:        loginID,
		Process:   login,
		NextStep:  firstStep,
		Override:  overrideLogin,
		Ctx:       ctx,
		CancelCtx: cancel,
	}
	go prov.handleLoginTimeout(provLogin)
	prov.loginsLock.Lock()
	prov.logins[loginID] = provLogin
	prov.loginsLock.Unlock()
	zerolog.Ctx(r.Context()).Info().
		Str("login_id", loginID).
		Any("first_step", firstStep).
		Msg("Created login process")
	exhttp.WriteJSONResponse(w, http.StatusOK, &RespSubmitLogin{LoginID: loginID, LoginStep: firstStep})
}

func (prov *ProvisioningAPI) PostLoginStep(w http.ResponseWriter, r *http.Request) {
	loginID := r.PathValue("loginProcessID")
	prov.loginsLock.RLock()
	login, ok := prov.logins[loginID]
	prov.loginsLock.RUnlock()
	if !ok {
		zerolog.Ctx(r.Context()).Warn().Str("login_id", loginID).Msg("Login not found")
		mautrix.MNotFound.WithMessage("Login not found").Write(w)
		return
	}
	stepID := r.PathValue("stepID")
	stepType := bridgev2.LoginStepType(r.PathValue("stepType"))
	var params map[string]string
	switch stepType {
	case bridgev2.LoginStepTypeUserInput, bridgev2.LoginStepTypeCookies:
		err := json.NewDecoder(r.Body).Decode(&params)
		if err != nil {
			zerolog.Ctx(r.Context()).Err(err).Msg("Failed to decode request body")
			mautrix.MNotJSON.WithMessage("Failed to decode request body").Write(w)
			return
		}
	case bridgev2.LoginStepTypeDisplayAndWait:
		// no params
	case bridgev2.LoginStepTypeComplete:
		// invalid type for POST
		fallthrough
	default:
		mautrix.MUnrecognized.WithMessage("Invalid step type %q", r.PathValue("stepType")).Write(w)
		return
	}
	resp, err := prov.doLoginStep(r.Context(), login, stepType, stepID, params)
	if err != nil {
		zerolog.Ctx(r.Context()).Err(err).Msg("Failed to complete login step")
		RespondWithError(w, err, "Internal error in login step")
	} else {
		exhttp.WriteJSONResponse(w, http.StatusOK, &RespSubmitLogin{LoginID: login.ID, LoginStep: resp})
	}
}

func (prov *ProvisioningAPI) PostLoginCancel(w http.ResponseWriter, r *http.Request) {
	loginID := r.PathValue("loginProcessID")
	prov.loginsLock.RLock()
	login, ok := prov.logins[loginID]
	prov.loginsLock.RUnlock()
	if !ok {
		zerolog.Ctx(r.Context()).Warn().Str("login_id", loginID).Msg("Login not found")
		mautrix.MNotFound.WithMessage("Login not found").Write(w)
		return
	}
	prov.deleteLogin(login, true)
	exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
}

func (prov *ProvisioningAPI) doLoginStep(
	ctx context.Context,
	login *ProvLogin,
	expectedType bridgev2.LoginStepType,
	expectedID string,
	params map[string]string,
) (*bridgev2.LoginStep, error) {
	log := zerolog.Ctx(ctx).With().Str("login_id", login.ID).Logger()
	var returnPrevIfMatch bool
	if !login.Lock.TryLock() {
		log.Warn().Msg("Failed to acquire login lock immediately")
		returnPrevIfMatch = true
		login.Lock.Lock()
	}
	defer login.Lock.Unlock()
	if login.Ctx.Err() != nil {
		prov.deleteLogin(login, true)
		return nil, fmt.Errorf("login context is done: %w", login.Ctx.Err())
	}

	if returnPrevIfMatch && login.PrevStep != nil && login.PrevStep.StepID == expectedID {
		log.Debug().
			Str("prev_step_id", login.PrevStep.StepID).
			Any("next_step", login.NextStep).
			Msg("Login step that failed to acquire lock requested previous ID, returning last response")
		return login.NextStep, nil
	}
	if login.NextStep.StepID != expectedID {
		log.Warn().
			Str("request_step_id", expectedID).
			Str("expected_step_id", login.NextStep.StepID).
			Msg("Step ID does not match")
		return nil, mautrix.MBadState.WithMessage("Step ID does not match")
	}
	if login.NextStep.Type != expectedType {
		log.Warn().
			Str("request_step_type", string(expectedType)).
			Str("expected_step_type", string(login.NextStep.Type)).
			Msg("Step type does not match")
		return nil, mautrix.MBadState.WithMessage("Step type does not match")
	}
	log.Debug().
		Str("step_id", login.NextStep.StepID).
		Str("step_type", string(login.NextStep.Type)).
		Msg("Submitting login step")
	var nextStep *bridgev2.LoginStep
	var err error
	switch login.NextStep.Type {
	case bridgev2.LoginStepTypeUserInput:
		nextStep, err = login.Process.(bridgev2.LoginProcessUserInput).SubmitUserInput(login.Ctx, params)
	case bridgev2.LoginStepTypeCookies:
		nextStep, err = login.Process.(bridgev2.LoginProcessCookies).SubmitCookies(login.Ctx, params)
	case bridgev2.LoginStepTypeDisplayAndWait:
		nextStep, err = login.Process.(bridgev2.LoginProcessDisplayAndWait).Wait(login.Ctx)
	default:
		panic("Impossible state")
	}
	if err != nil {
		prov.deleteLogin(login, true)
		return nil, err
	} else if nextStep == nil {
		prov.deleteLogin(login, true)
		return nil, ErrNilStep
	}
	login.PrevStep = login.NextStep
	login.NextStep = nextStep
	if nextStep.Type == bridgev2.LoginStepTypeComplete {
		prov.handleCompleteStep(login, nextStep)
	} else {
		log.Debug().Any("next_step", nextStep).Msg("Returning next login step")
	}
	return nextStep, nil
}

func (prov *ProvisioningAPI) handleCompleteStep(login *ProvLogin, step *bridgev2.LoginStep) {
	ctx := login.Ctx
	zerolog.Ctx(ctx).Info().
		Str("step_id", step.StepID).
		Str("user_login_id", string(step.CompleteParams.UserLoginID)).
		Msg("Login completed successfully")
	defer login.CancelCtx()
	prov.deleteLogin(login, false)
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
	}, bridgev2.DeleteOpts{LogoutRemote: true})
}

func (prov *ProvisioningAPI) handleLoginTimeout(login *ProvLogin) {
	<-login.Ctx.Done()
	if errors.Is(login.Ctx.Err(), context.DeadlineExceeded) {
		zerolog.Ctx(login.Ctx).Warn().Msg("Login process timed out, deleting")
		login.Process.Cancel()
		prov.loginsLock.Lock()
		delete(prov.logins, login.ID)
		prov.loginsLock.Unlock()
	}
}

func (prov *ProvisioningAPI) deleteLogin(login *ProvLogin, cancel bool) {
	if cancel {
		login.Process.Cancel()
		login.CancelCtx()
	}
	prov.loginsLock.Lock()
	delete(prov.logins, login.ID)
	prov.loginsLock.Unlock()
}
