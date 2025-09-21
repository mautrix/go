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
	SelfSign   bool `yaml:"self_sign"`

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
