// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Deprecated: use bridgev2/status
package status

import (
	"maunium.net/go/mautrix/bridgev2/status"
)

// Deprecated: use bridgev2/status
type (
	BridgeStateEvent                  = status.BridgeStateEvent
	BridgeStateErrorCode              = status.BridgeStateErrorCode
	BridgeStateErrorMap               = status.BridgeStateErrorMap
	BridgeState                       = status.BridgeState
	RemoteProfile                     = status.RemoteProfile
	GlobalBridgeState                 = status.GlobalBridgeState
	BridgeStateFiller                 = status.BridgeStateFiller
	StandaloneCustomBridgeStateFiller = status.StandaloneCustomBridgeStateFiller
	CustomBridgeStateFiller           = status.CustomBridgeStateFiller
	MessageCheckpointStep             = status.MessageCheckpointStep
	MessageCheckpointStatus           = status.MessageCheckpointStatus
	MessageCheckpointReportedBy       = status.MessageCheckpointReportedBy
	MessageCheckpoint                 = status.MessageCheckpoint
	CheckpointsJSON                   = status.CheckpointsJSON
	LocalBridgeAccountState           = status.LocalBridgeAccountState
	LocalBridgeDeviceState            = status.LocalBridgeDeviceState
)

// Deprecated: use bridgev2/status
const (
	StateStarting          = status.StateStarting
	StateUnconfigured      = status.StateUnconfigured
	StateRunning           = status.StateRunning
	StateBridgeUnreachable = status.StateBridgeUnreachable

	StateConnecting          = status.StateConnecting
	StateBackfilling         = status.StateBackfilling
	StateConnected           = status.StateConnected
	StateTransientDisconnect = status.StateTransientDisconnect
	StateBadCredentials      = status.StateBadCredentials
	StateUnknownError        = status.StateUnknownError
	StateLoggedOut           = status.StateLoggedOut

	MsgStepClient     = status.MsgStepClient
	MsgStepHomeserver = status.MsgStepHomeserver
	MsgStepBridge     = status.MsgStepBridge
	MsgStepDecrypted  = status.MsgStepDecrypted
	MsgStepRemote     = status.MsgStepRemote
	MsgStepCommand    = status.MsgStepCommand

	MsgStatusSuccess        = status.MsgStatusSuccess
	MsgStatusWillRetry      = status.MsgStatusWillRetry
	MsgStatusPermFailure    = status.MsgStatusPermFailure
	MsgStatusUnsupported    = status.MsgStatusUnsupported
	MsgStatusTimeout        = status.MsgStatusTimeout
	MsgStatusDelivered      = status.MsgStatusDelivered
	MsgStatusDeliveryFailed = status.MsgStatusDeliveryFailed

	MsgReportedByAsmux  = status.MsgReportedByAsmux
	MsgReportedByBridge = status.MsgReportedByBridge
	MsgReportedByHungry = status.MsgReportedByHungry

	LocalBridgeAccountStateSetup   = status.LocalBridgeAccountStateSetup
	LocalBridgeAccountStateDeleted = status.LocalBridgeAccountStateDeleted

	LocalBridgeDeviceStateSetup     = status.LocalBridgeDeviceStateSetup
	LocalBridgeDeviceStateLoggedOut = status.LocalBridgeDeviceStateLoggedOut
	LocalBridgeDeviceStateError     = status.LocalBridgeDeviceStateError
	LocalBridgeDeviceStateDeleted   = status.LocalBridgeDeviceStateDeleted
)

// Deprecated: use bridgev2/status
var (
	CheckpointTypes          = status.CheckpointTypes
	NewMessageCheckpoint     = status.NewMessageCheckpoint
	ReasonToCheckpointStatus = status.ReasonToCheckpointStatus
	BridgeStateHumanErrors   = status.BridgeStateHumanErrors
)
