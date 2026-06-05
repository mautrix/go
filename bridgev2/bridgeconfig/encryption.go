// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgeconfig

import (
	"maunium.net/go/mautrix/id"
)

type EncryptionConfig struct {
	Allow      bool `yaml:"allow"`
	Default    bool `yaml:"default"`
	Require    bool `yaml:"require"`
	Appservice bool `yaml:"appservice"`
	MSC4190    bool `yaml:"msc4190"`
	// MSC4350: Permitting encryption impersonation for appservices.
	// When enabled, the bridge will create an "impersonatable" device for
	// each ghost user (and double-puppeted real user) pointing at the
	// bridge bot's device as the impersonator. This lets recipient clients
	// legitimately accept events signed by the bridge bot's device when
	// attributed to a ghost, removing the "sender doesn't match device
	// owner" warning. Requires homeserver support for MSC4350 (synapse
	// experimental_features.msc4350_enabled) and a cross-signed bridge bot
	// device (encryption.self_sign).
	// See https://github.com/matrix-org/matrix-spec-proposals/pull/4350
	MSC4350  bool `yaml:"msc4350"`
	MSC4392  bool `yaml:"msc4392"`
	SelfSign bool `yaml:"self_sign"`

	PlaintextMentions bool `yaml:"plaintext_mentions"`

	PickleKey string `yaml:"pickle_key"`

	DeleteKeys struct {
		DeleteOutboundOnAck       bool `yaml:"delete_outbound_on_ack"`
		DontStoreOutbound         bool `yaml:"dont_store_outbound"`
		RatchetOnDecrypt          bool `yaml:"ratchet_on_decrypt"`
		DeleteFullyUsedOnDecrypt  bool `yaml:"delete_fully_used_on_decrypt"`
		DeletePrevOnNewSession    bool `yaml:"delete_prev_on_new_session"`
		DeleteOnDeviceDelete      bool `yaml:"delete_on_device_delete"`
		PeriodicallyDeleteExpired bool `yaml:"periodically_delete_expired"`
		DeleteOutdatedInbound     bool `yaml:"delete_outdated_inbound"`
	} `yaml:"delete_keys"`

	VerificationLevels struct {
		Receive id.TrustState `yaml:"receive"`
		Send    id.TrustState `yaml:"send"`
		Share   id.TrustState `yaml:"share"`
	} `yaml:"verification_levels"`
	AllowKeySharing bool `yaml:"allow_key_sharing"`

	Rotation struct {
		EnableCustom bool  `yaml:"enable_custom"`
		Milliseconds int64 `yaml:"milliseconds"`
		Messages     int   `yaml:"messages"`

		DisableDeviceChangeKeyRotation bool `yaml:"disable_device_change_key_rotation"`
	} `yaml:"rotation"`
}
