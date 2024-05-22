// Copyright (c) 2024 Sumner Evans
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package verificationhelper_test

import (
	"context"

	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type MockVerificationCallbacks interface {
	GetRequestedVerifications() map[id.UserID][]id.VerificationTransactionID
	GetScanQRCodeTransactions() []id.VerificationTransactionID
	GetQRCodeShown(id.VerificationTransactionID) *verificationhelper.QRCode
}

type baseVerificationCallbacks struct {
	scanQRCodeTransactions   []id.VerificationTransactionID
	verificationsRequested   map[id.UserID][]id.VerificationTransactionID
	qrCodesShown             map[id.VerificationTransactionID]*verificationhelper.QRCode
	qrCodesScanned           map[id.VerificationTransactionID]struct{}
	doneTransactions         map[id.VerificationTransactionID]struct{}
	verificationCancellation map[id.VerificationTransactionID]*event.VerificationCancelEventContent
}

func newBaseVerificationCallbacks() *baseVerificationCallbacks {
	return &baseVerificationCallbacks{
		verificationsRequested:   map[id.UserID][]id.VerificationTransactionID{},
		qrCodesShown:             map[id.VerificationTransactionID]*verificationhelper.QRCode{},
		qrCodesScanned:           map[id.VerificationTransactionID]struct{}{},
		doneTransactions:         map[id.VerificationTransactionID]struct{}{},
		verificationCancellation: map[id.VerificationTransactionID]*event.VerificationCancelEventContent{},
	}
}

func (c *baseVerificationCallbacks) GetRequestedVerifications() map[id.UserID][]id.VerificationTransactionID {
	return c.verificationsRequested
}

func (c *baseVerificationCallbacks) GetScanQRCodeTransactions() []id.VerificationTransactionID {
	return c.scanQRCodeTransactions
}

func (c *baseVerificationCallbacks) GetQRCodeShown(txnID id.VerificationTransactionID) *verificationhelper.QRCode {
	return c.qrCodesShown[txnID]
}

func (c *baseVerificationCallbacks) WasOurQRCodeScanned(txnID id.VerificationTransactionID) bool {
	_, ok := c.qrCodesScanned[txnID]
	return ok
}

func (c *baseVerificationCallbacks) IsVerificationDone(txnID id.VerificationTransactionID) bool {
	_, ok := c.doneTransactions[txnID]
	return ok
}

func (c *baseVerificationCallbacks) GetVerificationCancellation(txnID id.VerificationTransactionID) *event.VerificationCancelEventContent {
	return c.verificationCancellation[txnID]
}

func (c *baseVerificationCallbacks) VerificationRequested(ctx context.Context, txnID id.VerificationTransactionID, from id.UserID) {
	c.verificationsRequested[from] = append(c.verificationsRequested[from], txnID)
}

func (c *baseVerificationCallbacks) VerificationCancelled(ctx context.Context, txnID id.VerificationTransactionID, code event.VerificationCancelCode, reason string) {
	c.verificationCancellation[txnID] = &event.VerificationCancelEventContent{
		Code:   code,
		Reason: reason,
	}
}

func (c *baseVerificationCallbacks) VerificationDone(ctx context.Context, txnID id.VerificationTransactionID) {
	c.doneTransactions[txnID] = struct{}{}
}

type sasVerificationCallbacks struct {
	*baseVerificationCallbacks
}

func newSASVerificationCallbacks() *sasVerificationCallbacks {
	return &sasVerificationCallbacks{newBaseVerificationCallbacks()}
}

func newSASVerificationCallbacksWithBase(base *baseVerificationCallbacks) *sasVerificationCallbacks {
	return &sasVerificationCallbacks{base}
}

func (*sasVerificationCallbacks) ShowSAS(ctx context.Context, txnID id.VerificationTransactionID, emojis []rune, decimals []int) {
	panic("show sas")
}

type qrCodeVerificationCallbacks struct {
	*baseVerificationCallbacks
}

func newQRCodeVerificationCallbacks() *qrCodeVerificationCallbacks {
	return &qrCodeVerificationCallbacks{newBaseVerificationCallbacks()}
}

func newQRCodeVerificationCallbacksWithBase(base *baseVerificationCallbacks) *qrCodeVerificationCallbacks {
	return &qrCodeVerificationCallbacks{base}
}

func (c *qrCodeVerificationCallbacks) ScanQRCode(ctx context.Context, txnID id.VerificationTransactionID) {
	c.scanQRCodeTransactions = append(c.scanQRCodeTransactions, txnID)
}

func (c *qrCodeVerificationCallbacks) ShowQRCode(ctx context.Context, txnID id.VerificationTransactionID, qrCode *verificationhelper.QRCode) {
	c.qrCodesShown[txnID] = qrCode
}

func (c *qrCodeVerificationCallbacks) QRCodeScanned(ctx context.Context, txnID id.VerificationTransactionID) {
	c.qrCodesScanned[txnID] = struct{}{}
}

type allVerificationCallbacks struct {
	*baseVerificationCallbacks
	*sasVerificationCallbacks
	*qrCodeVerificationCallbacks
}

func newAllVerificationCallbacks() *allVerificationCallbacks {
	base := newBaseVerificationCallbacks()
	return &allVerificationCallbacks{
		base,
		newSASVerificationCallbacksWithBase(base),
		newQRCodeVerificationCallbacksWithBase(base),
	}
}
