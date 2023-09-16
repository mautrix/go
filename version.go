package mautrix

import (
	"fmt"
	"regexp"
	"runtime"
	"strings"
)

const Version = "v0.16.1"

var GoModVersion = ""
var Commit = ""
var VersionWithCommit = Version

var DefaultUserAgent = "mautrix-go/" + Version + " go/" + strings.TrimPrefix(runtime.Version(), "go")

var goModVersionRegex = regexp.MustCompile(`v.+\d{14}-([0-9a-f]{12})`)

func init() {
	if GoModVersion != "" {
		match := goModVersionRegex.FindStringSubmatch(GoModVersion)
		if match != nil {
			Commit = match[1]
		}
	}
	if Commit != "" {
		VersionWithCommit = fmt.Sprintf("%s+dev.%s", Version, Commit[:8])
		DefaultUserAgent = strings.Replace(DefaultUserAgent, "mautrix-go/"+Version, "mautrix-go/"+VersionWithCommit, 1)
	}
}
