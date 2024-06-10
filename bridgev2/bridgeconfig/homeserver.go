// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgeconfig

type HomeserverSoftware string

const (
	SoftwareStandard HomeserverSoftware = "standard"
	SoftwareAsmux    HomeserverSoftware = "asmux"
	SoftwareHungry   HomeserverSoftware = "hungry"
)

var AllowedHomeserverSoftware = map[HomeserverSoftware]bool{
	SoftwareStandard: true,
	SoftwareAsmux:    true,
	SoftwareHungry:   true,
}

type HomeserverConfig struct {
	Address    string `yaml:"address"`
	Domain     string `yaml:"domain"`
	AsyncMedia bool   `yaml:"async_media"`

	PublicAddress string `yaml:"public_address,omitempty"`

	Software HomeserverSoftware `yaml:"software"`

	StatusEndpoint                string `yaml:"status_endpoint"`
	MessageSendCheckpointEndpoint string `yaml:"message_send_checkpoint_endpoint"`

	Websocket      bool   `yaml:"websocket"`
	WSProxy        string `yaml:"websocket_proxy"`
	WSPingInterval int    `yaml:"ping_interval_seconds"`
}
