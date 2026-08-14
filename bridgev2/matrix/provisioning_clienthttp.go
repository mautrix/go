// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/rs/xid"
	"github.com/rs/zerolog"
	"go.mau.fi/util/exhttp"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
)

var _ http.RoundTripper = (*ProvLogin)(nil)

func (prov *ProvisioningAPI) PostLoginClientHTTP(w http.ResponseWriter, r *http.Request) {
	log := zerolog.Ctx(r.Context())
	loginID := r.PathValue("loginProcessID")
	txnID := r.PathValue("txnID")
	reqID := r.PathValue("reqID")
	prov.loginsLock.RLock()
	login, ok := prov.logins[loginID]
	prov.loginsLock.RUnlock()
	if !ok {
		log.Warn().Str("login_id", loginID).Msg("Login not found")
		mautrix.MNotFound.WithMessage("Login not found").Write(w)
		return
	}
	var resp bridgev2.LoginClientHTTPResponse
	err := json.NewDecoder(r.Body).Decode(&resp)
	if err != nil {
		log.Err(err).Msg("Failed to decode request body")
		mautrix.MNotJSON.WithMessage("Failed to decode request body").Write(w)
		return
	} else if !resp.IsValid() {
		mautrix.MBadJSON.WithMessage("Invalid client HTTP response payload in body").Write(w)
		return
	}
	var currentStep *bridgev2.LoginStep
	var stepWaitChan chan struct{}
	err = login.step.WithLock(func(sm *stepManager) error {
		if sm.err != nil {
			return sm.err
		}
		currentStep = sm.next
		if sm.prev != nil && sm.prev.TxnID == txnID && sm.prev.StepID == reqID && sm.prev.Type == bridgev2.LoginStepTypeClientHTTP {
			return errReturnCurrentStep
		} else if sm.next.Type != bridgev2.LoginStepTypeClientHTTP {
			return mautrix.MBadState.WithMessage("Next step type is not client_http")
		} else if sm.next.TxnID != txnID {
			return mautrix.MBadState.WithMessage("Transaction ID does not match")
		} else if sm.next.ClientHTTPParams.RequestID != reqID {
			return mautrix.MBadState.WithMessage("Request ID does not match")
		}
		if sm.pendingHTTP != nil {
			select {
			case sm.pendingHTTP <- &resp:
				log.Debug().
					Str("req_id", reqID).
					Int("status_code", resp.StatusCode).
					Int("header_count", len(resp.Headers)).
					Int("body_length", len(resp.Body)).
					Str("error_msg", resp.Error).
					Msg("Submitted client HTTP response")
			default:
				return fmt.Errorf("pendingHTTP channel unexpectedly didn't accept response")
			}
			sm.pendingHTTP = nil
			sm.wait = make(chan struct{})
		} else {
			log.Debug().Str("req_id", reqID).
				Msg("Client HTTP response was already submitted, ignoring new data")
		}
		stepWaitChan = sm.wait
		return nil
	})
	if errors.Is(err, errReturnCurrentStep) {
		exhttp.WriteJSONResponse(w, http.StatusOK, &RespSubmitLogin{LoginID: login.ID, LoginStep: currentStep})
		return
	} else if err != nil {
		log.Err(err).Msg("Client HTTP step rejected in pre-validation")
		RespondWithError(w, err, "Internal error in login step validation")
		return
	}
	select {
	case <-stepWaitChan:
	case <-r.Context().Done():
		log.Warn().Str("req_id", reqID).Msg("Client HTTP step context canceled")
		w.WriteHeader(499)
		return
	}
	nextStep, err := login.step.GetNext()
	// Check the actual error before checking if the context expired, because if there was an
	// error, then we already deleted the login session, which canceled the context.
	if err != nil {
		log.Err(err).Str("req_id", reqID).Msg("Client HTTP step failed")
		RespondWithError(w, err, "Internal error in login step")
	} else if login.Ctx.Err() != nil && nextStep != nil && nextStep.Type != bridgev2.LoginStepTypeComplete {
		if errors.Is(login.Ctx.Err(), context.DeadlineExceeded) {
			ErrLoginTimedOut.Write(w)
		} else {
			ErrLoginCancelled.Write(w)
		}
	} else {
		exhttp.WriteJSONResponse(w, http.StatusOK, &RespSubmitLogin{LoginID: login.ID, LoginStep: nextStep})
	}
}

func (p *ProvLogin) RoundTrip(req *http.Request) (*http.Response, error) {
	log := zerolog.Ctx(req.Context()).With().Str("login_id", p.ID).Logger()
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
	}
	if !p.HTTPLock.TryLock() {
		return nil, fmt.Errorf("illegal client HTTP request: another request already in progress")
	}
	defer p.HTTPLock.Unlock()
	ch := make(chan *bridgev2.LoginClientHTTPResponse, 1)
	err := p.step.WithLock(func(sm *stepManager) error {
		if sm.err != nil {
			return fmt.Errorf("login is errored: %w", sm.err)
		}
		if !sm.started {
			return fmt.Errorf("illegal client HTTP request: no ongoing step")
		}
		sm.prev = sm.next
		txnID := LoginStepTxnIDPrefix + xid.New().String()
		if sm.prev != nil {
			txnID = sm.prev.TxnID
		}
		sm.reqCounter++
		reqID := "fi.mau.bridgev2.client_http." + strconv.Itoa(sm.reqCounter)
		sm.next = &bridgev2.LoginStep{
			Type:   bridgev2.LoginStepTypeClientHTTP,
			StepID: reqID,
			TxnID:  txnID,
			ClientHTTPParams: &bridgev2.LoginClientHTTPParams{
				RequestID: reqID,
				Method:    req.Method,
				URL:       req.URL.String(),
				Headers:   req.Header,
				Body:      body,
			},
		}
		sm.pendingHTTP = ch
		if sm.wait != nil {
			close(sm.wait)
			sm.wait = nil
			log.Debug().
				Str("req_id", reqID).
				Str("method", req.Method).
				Stringer("url", req.URL).
				Msg("Waiting for client HTTP response")
		} else {
			// This should probably never happen
			log.Warn().
				Str("req_id", reqID).
				Str("method", req.Method).
				Stringer("url", req.URL).
				Msg("Login step isn't waiting when client http request was made")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var resp *bridgev2.LoginClientHTTPResponse
	select {
	case resp = <-ch:
		// yay
	case <-p.Ctx.Done():
		log.Warn().Msg("Login context cancelled during client HTTP request")
		return nil, fmt.Errorf("login context cancelled during client HTTP request: %w", p.Ctx.Err())
	case <-req.Context().Done():
		log.Warn().Err(req.Context().Err()).Msg("Client HTTP request canceled")
		p.CancelCtx()
		return nil, req.Context().Err()
	}
	if resp.Error != "" {
		return nil, errors.New(ErrorFromClientPrefix + resp.Error)
	}
	if resp.Headers == nil {
		resp.Headers = make(http.Header)
	} else {
		for key, values := range resp.Headers {
			canon := http.CanonicalHeaderKey(key)
			if canon != key {
				resp.Headers[canon] = append(resp.Headers[canon], values...)
				delete(resp.Headers, key)
			}
		}
	}
	finalURL, _ := url.Parse(resp.FinalURL)
	if finalURL == nil || resp.FinalURL == "" {
		finalURL = req.URL
	}
	return &http.Response{
		Status:        fmt.Sprintf("%d Meow", resp.StatusCode),
		StatusCode:    resp.StatusCode,
		Proto:         ClientHTTPProto,
		ProtoMajor:    1,
		Header:        resp.Headers,
		Body:          io.NopCloser(bytes.NewReader(resp.Body)),
		ContentLength: int64(len(resp.Body)),
		Request: &http.Request{
			Method: req.Method,
			URL:    finalURL,
		},
	}, nil
}

// Note: bridges may check these without referencing the constants, so they shouldn't be changed
const (
	ErrorFromClientPrefix = "error from client: "
	ClientHTTPProto       = "MauClientHTTP/1.0"
)
