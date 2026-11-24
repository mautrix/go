// Copyright (c) 2026 Nick Mills-Barrett
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgeconfig

import (
	up "go.mau.fi/util/configupgrade"
)

type ProxyConfig struct {
	URL       string `yaml:"url"`
	LookupURL string `yaml:"lookup_url"`
}

func (pc *ProxyConfig) IsConfigured() bool {
	return pc.URL != "" || pc.LookupURL != ""
}

func MigrateNetworkProxyConfig(helper up.Helper) {
	if _, ok := helper.Get(up.Str, "proxy", "url"); ok {
		return
	} else if _, ok = helper.Get(up.Str, "proxy", "lookup_url"); ok {
		return
	}
	CopyToOtherLocation(helper, up.Str, []string{"network", "proxy"}, []string{"proxy", "url"})
	CopyToOtherLocation(helper, up.Str, []string{"network", "get_proxy_url"}, []string{"proxy", "lookup_url"})
	CopyToOtherLocation(helper, up.Str, []string{"network", "get_proxy_from"}, []string{"proxy", "lookup_url"})
}
