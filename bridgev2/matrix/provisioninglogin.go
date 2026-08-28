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
	"io"
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

type stepManager struct {
	next    *bridgev2.LoginStep
	prev    *bridgev2.LoginStep
	started bool
	wait    chan struct{}
	lock    sync.Mutex
	err     error

	reqCounter int

	pendingHTTP chan *bridgev2.LoginClientHTTPResponse
	stepCancel  context.CancelCauseFunc
	stepResult  *stepExecutionResult
	cancelling  bool
}

type stepExecutionResult struct {
	err error
}

func (sm *stepManager) GetNext() (*bridgev2.LoginStep, error) {
	sm.lock.Lock()
	defer sm.lock.Unlock()
	return sm.next, sm.err
}

func (sm *stepManager) WithLock(fn func(*stepManager) error) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()
	return fn(sm)
}

func (sm *stepManager) WithNonErroringLock(fn func(*stepManager)) {
	sm.lock.Lock()
	defer sm.lock.Unlock()
	fn(sm)
}

type ProvLogin struct {
	ID       string
	Process  bridgev2.LoginProcess
	step     *stepManager
	Override *bridgev2.UserLogin

	HTTPLock sync.Mutex

	Ctx       context.Context
	CancelCtx context.CancelFunc
}

var ErrNilStep = errors.New("bridge returned nil step with no error")
var ErrTooManyLogins = bridgev2.RespError{ErrCode: "FI.MAU.BRIDGE.TOO_MANY_LOGINS", Err: "Maximum number of logins exceeded", StatusCode: http.StatusForbidden}
var ErrLoginCancelled = bridgev2.RespError{ErrCode: "FI.MAU.BRIDGE.LOGIN_CANCELLED", Err: "Login process was cancelled", StatusCode: http.StatusGone}
var ErrLoginTimedOut = bridgev2.RespError{ErrCode: "FI.MAU.BRIDGE.LOGIN_TIMED_OUT", Err: "Login process timed out", StatusCode: http.StatusGone}
var ErrLoginAlreadyFinished = bridgev2.RespError{ErrCode: "FI.MAU.BRIDGE.LOGIN_ALREADY_FINISHED", Err: "Login process was already finished", StatusCode: http.StatusGone}

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
	loginID := xid.New().String()
	ctx, cancel := context.WithTimeout(prov.br.Bridge.BackgroundCtx, 30*time.Minute)
	ctx = user.Log.With().
		Str("login_id", loginID).
		Logger().WithContext(ctx)
	ch := make(chan struct{})
	provLogin := &ProvLogin{
		ID:        loginID,
		Process:   login,
		Override:  overrideLogin,
		Ctx:       ctx,
		CancelCtx: cancel,
		step: &stepManager{
			started: true,
			wait:    ch,
		},
	}
	go prov.handleLoginTimeout(provLogin)
	prov.loginsLock.Lock()
	prov.logins[loginID] = provLogin
	prov.loginsLock.Unlock()
	zerolog.Ctx(r.Context()).Info().
		Str("login_id", loginID).
		Msg("Created login process, now starting")

	var rt http.RoundTripper
	if r.URL.Query().Get("client_http") == "1" {
		rt = provLogin
	}
	go prov.executeStep(provLogin, provLogin.Ctx, "start", nil, nil, &bridgev2.LoginStartParams{
		Override: overrideLogin,
		HTTP:     rt,
	}, nil)
	select {
	case <-ch:
	case <-r.Context().Done():
		prov.deleteLogin(provLogin, true, ErrLoginCancelled)
		return
	}
	firstStep, err := provLogin.step.GetNext()
	if err != nil {
		zerolog.Ctx(r.Context()).Err(err).Msg("Failed to start login")
		RespondWithError(w, err, "Internal error starting login")
		return
	}
	zerolog.Ctx(r.Context()).Info().
		Str("login_id", loginID).
		Any("first_step", firstStep).
		Msg("Started login process")
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
	txnID := r.URL.Query().Get("txn_id")
	stepID := r.PathValue("stepID")
	stepType := bridgev2.LoginStepType(r.PathValue("stepType"))
	var params map[string]string
	var rawParams json.RawMessage
	switch stepType {
	case bridgev2.LoginStepTypeUserInput, bridgev2.LoginStepTypeCookies:
		err := json.NewDecoder(r.Body).Decode(&params)
		if err != nil {
			zerolog.Ctx(r.Context()).Err(err).Msg("Failed to decode request body")
			mautrix.MNotJSON.WithMessage("Failed to decode request body").Write(w)
			return
		}
	case bridgev2.LoginStepTypeWebAuthn:
		var err error
		rawParams, err = io.ReadAll(r.Body)
		if err != nil {
			zerolog.Ctx(r.Context()).Err(err).Msg("Failed to read request body")
			mautrix.MNotJSON.WithMessage("Failed to read request body").Write(w)
			return
		} else if !json.Valid(rawParams) {
			mautrix.MNotJSON.WithMessage("Request body is not valid JSON").Write(w)
			return
		}
	case bridgev2.LoginStepTypeDisplayAndWait:
		// no params
	case bridgev2.LoginStepTypeComplete:
		ErrLoginAlreadyFinished.Write(w)
		return
	default:
		mautrix.MUnrecognized.WithMessage("Invalid step type %q", r.PathValue("stepType")).Write(w)
		return
	}
	resp, err := prov.doLoginStep(r.Context(), login, stepType, stepID, txnID, params, rawParams)
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
	prov.deleteLogin(login, true, ErrLoginCancelled)
	exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
}

func (prov *ProvisioningAPI) PostLoginStepCancel(w http.ResponseWriter, r *http.Request) {
	loginID := r.PathValue("loginProcessID")
	prov.loginsLock.RLock()
	login, ok := prov.logins[loginID]
	prov.loginsLock.RUnlock()
	if !ok {
		mautrix.MNotFound.WithMessage("Login not found").Write(w)
		return
	}
	nextStep, err := prov.cancelLoginStep(r.Context(), login, r.PathValue("stepID"), r.URL.Query().Get("txn_id"))
	if err != nil {
		zerolog.Ctx(r.Context()).Err(err).Msg("Failed to cancel login step")
		RespondWithError(w, err, "Internal error cancelling login step")
	} else {
		exhttp.WriteJSONResponse(w, http.StatusOK, &RespSubmitLogin{LoginID: login.ID, LoginStep: nextStep})
	}
}

const LoginStepTxnIDPrefix = "bls_"

var errReturnCurrentStep = errors.New("return current step")

func (prov *ProvisioningAPI) cancelLoginStep(
	ctx context.Context,
	login *ProvLogin,
	expectedID string,
	expectedTxnID string,
) (*bridgev2.LoginStep, error) {
	var currentStep *bridgev2.LoginStep
	var stepWaitChan chan struct{}
	var stepResult *stepExecutionResult
	err := login.step.WithLock(func(sm *stepManager) error {
		if sm.err != nil {
			return sm.err
		}
		currentStep = sm.next
		if sm.prev != nil && expectedTxnID != "" && sm.prev.TxnID == expectedTxnID {
			return errReturnCurrentStep
		} else if currentStep.StepID != expectedID {
			return mautrix.MBadState.WithMessage("Step ID does not match")
		} else if expectedTxnID != "" && currentStep.TxnID != expectedTxnID {
			return mautrix.MBadState.WithMessage("Transaction ID does not match")
		}

		if _, ok := login.Process.(bridgev2.LoginProcessStepCancel); !ok {
			return mautrix.MBadState.WithMessage("Login process does not support cancelling steps")
		}
		var canCancel bool
		switch currentStep.Type {
		case bridgev2.LoginStepTypeDisplayAndWait:
			canCancel = currentStep.DisplayAndWaitParams != nil && currentStep.DisplayAndWaitParams.CanCancel
		case bridgev2.LoginStepTypeUserInput:
			canCancel = currentStep.UserInputParams != nil && currentStep.UserInputParams.CanCancel
		default:
			return mautrix.MBadState.WithMessage("Login step type cannot be cancelled")
		}
		if !canCancel {
			return mautrix.MBadState.WithMessage("Login step cannot be cancelled")
		}

		if sm.cancelling {
			stepWaitChan = sm.wait
			stepResult = sm.stepResult
			return nil
		} else if currentStep.Type == bridgev2.LoginStepTypeDisplayAndWait && sm.started && sm.stepCancel != nil {
			sm.stepCancel(bridgev2.ErrLoginStepCancelled)
			stepWaitChan = sm.wait
			stepResult = sm.stepResult
		} else if sm.started {
			return mautrix.MBadState.WithMessage("Login step is already being submitted")
		}
		return nil
	})
	if errors.Is(err, errReturnCurrentStep) {
		return currentStep, nil
	} else if err != nil {
		return nil, fmt.Errorf("step cancellation validation failed: %w", err)
	}
	if stepWaitChan != nil {
		select {
		case <-stepWaitChan:
			if stepResult != nil && stepResult.err != nil && !errors.Is(stepResult.err, bridgev2.ErrLoginStepCancelled) {
				return nil, stepResult.err
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	err = login.step.WithLock(func(sm *stepManager) error {
		if sm.err != nil {
			return sm.err
		} else if sm.next != currentStep {
			return errReturnCurrentStep
		} else if sm.cancelling {
			stepWaitChan = sm.wait
			stepResult = sm.stepResult
			return nil
		}
		sm.started = true
		sm.cancelling = true
		sm.wait = make(chan struct{})
		sm.stepResult = &stepExecutionResult{}
		stepWaitChan = sm.wait
		stepResult = sm.stepResult
		go prov.executeStep(login, login.Ctx, "cancel_step", nil, nil, nil, stepResult)
		return nil
	})
	if errors.Is(err, errReturnCurrentStep) {
		return login.step.GetNext()
	} else if err != nil {
		return nil, err
	}
	select {
	case <-stepWaitChan:
		if stepResult.err != nil {
			return nil, stepResult.err
		}
		return login.step.GetNext()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (prov *ProvisioningAPI) doLoginStep(
	ctx context.Context,
	login *ProvLogin,
	expectedType bridgev2.LoginStepType,
	expectedID string,
	expectedTxnID string,
	params map[string]string,
	rawParams json.RawMessage,
) (*bridgev2.LoginStep, error) {
	log := zerolog.Ctx(ctx).With().Str("login_id", login.ID).Logger()
	if login.Ctx.Err() != nil {
		prov.deleteLogin(login, true, nil)
		if nextStep, err := login.step.GetNext(); nextStep != nil && nextStep.Type == bridgev2.LoginStepTypeComplete {
			return nextStep, nil
		} else if err != nil {
			return nil, err
		} else if errors.Is(login.Ctx.Err(), context.DeadlineExceeded) {
			return nil, ErrLoginTimedOut
		}
		return nil, ErrLoginCancelled
	}

	var currentStep *bridgev2.LoginStep
	var stepWaitChan chan struct{}
	var stepResult *stepExecutionResult
	err := login.step.WithLock(func(sm *stepManager) error {
		if sm.err != nil {
			return sm.err
		}
		currentStep = sm.next
		if sm.prev != nil && ((sm.started && sm.prev.StepID == expectedID) ||
			(expectedTxnID != "" && sm.prev.TxnID == expectedTxnID)) {
			log.Debug().
				Str("prev_step_id", sm.prev.StepID).
				Str("prev_step_txn_id", sm.prev.TxnID).
				Any("next_step", currentStep).
				Msg("Login step requested previous ID, returning last response")
			return errReturnCurrentStep
		}
		if currentStep.StepID != expectedID {
			return mautrix.MBadState.WithMessage("Step ID does not match")
		}
		if expectedTxnID != "" && currentStep.TxnID != expectedTxnID {
			return mautrix.MBadState.WithMessage("Transaction ID does not match")
		}
		if currentStep.Type != expectedType {
			return mautrix.MBadState.WithMessage("Step type does not match")
		}
		if !sm.started {
			sm.started = true
			sm.wait = make(chan struct{})
			log.Debug().
				Str("step_id", currentStep.StepID).
				Str("step_type", string(currentStep.Type)).
				Msg("Submitting login step")
			stepCtx, cancel := context.WithCancelCause(login.Ctx)
			sm.stepCancel = cancel
			sm.stepResult = &stepExecutionResult{}
			go prov.executeStep(login, stepCtx, currentStep.Type, params, rawParams, nil, sm.stepResult)
		} else {
			log.Debug().
				Str("step_id", currentStep.StepID).
				Msg("Login step was already started, not submitting again")
		}
		stepWaitChan = sm.wait
		stepResult = sm.stepResult
		return nil
	})
	if errors.Is(err, errReturnCurrentStep) {
		return currentStep, nil
	} else if err != nil {
		return nil, fmt.Errorf("step validation failed: %w", err)
	}
	select {
	case <-stepWaitChan:
		if stepResult != nil && stepResult.err != nil {
			return nil, stepResult.err
		}
		nextStep, err := login.step.GetNext()
		log.Debug().
			Any("next_step", nextStep).
			AnErr("step_error", err).
			Msg("Returning next login step")
		return nextStep, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (prov *ProvisioningAPI) executeStep(
	login *ProvLogin,
	ctx context.Context,
	currentStepType bridgev2.LoginStepType,
	params map[string]string,
	rawParams json.RawMessage,
	startParams *bridgev2.LoginStartParams,
	stepResult *stepExecutionResult,
) {
	var nextStep *bridgev2.LoginStep
	var err error
	switch currentStepType {
	case bridgev2.LoginStepTypeUserInput:
		nextStep, err = login.Process.(bridgev2.LoginProcessUserInput).SubmitUserInput(ctx, params)
	case "cancel_step":
		nextStep, err = login.Process.(bridgev2.LoginProcessStepCancel).CancelStep(ctx)
	case bridgev2.LoginStepTypeCookies:
		nextStep, err = login.Process.(bridgev2.LoginProcessCookies).SubmitCookies(ctx, params)
	case bridgev2.LoginStepTypeDisplayAndWait:
		nextStep, err = login.Process.(bridgev2.LoginProcessDisplayAndWait).Wait(ctx)
	case bridgev2.LoginStepTypeWebAuthn:
		nextStep, err = login.Process.(bridgev2.LoginProcessWebAuthn).SubmitWebAuthnResponse(ctx, rawParams)
	case "start":
		if startParams == nil {
			panic("Impossible state")
		}
		if paramable, ok := login.Process.(bridgev2.LoginProcessWithParams); ok {
			nextStep, err = paramable.StartWithParams(ctx, *startParams)
		} else if overridable, ok := login.Process.(bridgev2.LoginProcessWithOverride); ok && startParams.Override != nil {
			nextStep, err = overridable.StartWithOverride(ctx, startParams.Override)
		} else {
			nextStep, err = login.Process.Start(ctx)
		}
	default:
		panic("Impossible state")
	}
	if errors.Is(err, bridgev2.ErrLoginStepCancelled) && currentStepType == bridgev2.LoginStepTypeDisplayAndWait {
		login.step.WithNonErroringLock(func(sm *stepManager) {
			stepResult.err = err
			sm.started = false
			sm.stepCancel = nil
			if sm.wait != nil {
				close(sm.wait)
				sm.wait = nil
			}
		})
		return
	}
	if nextStep != nil {
		switch nextStep.Type {
		case bridgev2.LoginStepTypeUserInput, bridgev2.LoginStepTypeCookies, bridgev2.LoginStepTypeDisplayAndWait, bridgev2.LoginStepTypeComplete:
			// ok
		case bridgev2.LoginStepTypeWebAuthn:
			if prov.br.Config.Provisioning.FailOnWebAuthn {
				zerolog.Ctx(login.Ctx).Warn().Msg("Got WebAuthn step, failing login")
				err = bridgev2.RespError{
					ErrCode:    "COM.BEEPER.WEBAUTHN_UNSUPPORTED",
					Err:        "Logging in with a passkey is not yet supported",
					StatusCode: http.StatusBadRequest,
				}
			}
		default:
			err = fmt.Errorf("invalid response step type %q from login process", nextStep.Type)
		}
	}
	if err != nil {
		prov.deleteLogin(login, true, err)
		return
	} else if nextStep == nil {
		prov.deleteLogin(login, true, ErrNilStep)
		return
	}
	nextStep.TxnID = LoginStepTxnIDPrefix + xid.New().String()
	login.step.WithNonErroringLock(func(sm *stepManager) {
		finishStep(sm, nextStep, login)
	})
	if nextStep.Type == bridgev2.LoginStepTypeComplete {
		prov.handleCompleteStep(login, nextStep)
	}
}

func finishStep(sm *stepManager, nextStep *bridgev2.LoginStep, login *ProvLogin) {
	sm.prev = sm.next
	sm.next = nextStep
	sm.started = false
	sm.stepCancel = nil
	sm.stepResult = nil
	sm.cancelling = false
	if sm.wait != nil {
		close(sm.wait)
		sm.wait = nil
	} else {
		// This can happen if the login fails in the middle of a RoundTrip call
		zerolog.Ctx(login.Ctx).Warn().Msg("Login step isn't waiting when submit returned")
	}
}

func (prov *ProvisioningAPI) handleCompleteStep(login *ProvLogin, step *bridgev2.LoginStep) {
	ctx := login.Ctx
	zerolog.Ctx(ctx).Info().
		Str("step_id", step.StepID).
		Str("user_login_id", string(step.CompleteParams.UserLoginID)).
		Msg("Login completed successfully")
	defer login.CancelCtx()
	prov.deleteLogin(login, false, nil)
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

func (prov *ProvisioningAPI) deleteLogin(login *ProvLogin, cancel bool, err error) {
	if cancel {
		login.Process.Cancel()
		login.CancelCtx()
		login.step.WithNonErroringLock(func(sm *stepManager) {
			if sm.err == nil {
				sm.err = err
			}
			if sm.wait != nil {
				close(sm.wait)
				sm.wait = nil
			}
		})
	}
	prov.loginsLock.Lock()
	delete(prov.logins, login.ID)
	prov.loginsLock.Unlock()
}
