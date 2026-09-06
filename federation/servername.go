// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package federation

import (
	"net"
	"strconv"
	"strings"
)

func isSpecCompliantIPv6(host string) bool {
	// IPv6address = 2*45IPv6char
	// IPv6char    = DIGIT / %x41-46 / %x61-66 / ":" / "."
	//                  ; 0-9, A-F, a-f, :, .
	if len(host) < 2 || len(host) > 45 {
		return false
	}
	for _, ch := range host {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') && (ch < 'A' || ch > 'F') && ch != ':' && ch != '.' {
			return false
		}
	}
	return true
}

func isValidIPv4Chunk(str string) bool {
	if len(str) == 0 || len(str) > 3 {
		return false
	}
	for _, ch := range str {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true

}

func isSpecCompliantIPv4(host string) bool {
	// IPv4address = 1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT
	if len(host) < 7 || len(host) > 15 {
		return false
	}
	parts := strings.Split(host, ".")
	return len(parts) == 4 &&
		isValidIPv4Chunk(parts[0]) &&
		isValidIPv4Chunk(parts[1]) &&
		isValidIPv4Chunk(parts[2]) &&
		isValidIPv4Chunk(parts[3])
}

func isSpecCompliantDNSName(host string) bool {
	// dns-name    = 1*255dns-char
	// dns-char    = DIGIT / ALPHA / "-" / "."
	if len(host) == 0 || len(host) > 255 {
		return false
	}
	for _, ch := range host {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && ch != '-' && ch != '.' {
			return false
		}
	}
	return true
}

// ParseServerName parses the port and hostname from a Matrix server name and validates that
// it matches the grammar specified in https://spec.matrix.org/v1.11/appendices/#server-name
func ParseServerName(serverName string) (host string, port uint16, ok bool) {
	if len(serverName) == 0 || len(serverName) > 255 {
		return
	}
	colonIdx := strings.LastIndexByte(serverName, ':')
	if colonIdx > 0 {
		u64Port, err := strconv.ParseUint(serverName[colonIdx+1:], 10, 16)
		if err == nil {
			port = uint16(u64Port)
			serverName = serverName[:colonIdx]
		}
	}
	if serverName[0] == '[' {
		if serverName[len(serverName)-1] != ']' {
			return
		}
		host = serverName[1 : len(serverName)-1]
		ok = isSpecCompliantIPv6(host) && net.ParseIP(host) != nil
	} else {
		host = serverName
		ok = isSpecCompliantDNSName(host) || isSpecCompliantIPv4(host)
	}
	return
}
