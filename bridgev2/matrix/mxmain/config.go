// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mxmain

import (
	_ "embed"
	"strings"
	"text/template"

	"go.mau.fi/util/exerrors"
)

//go:embed example-config.yaml
var MatrixExampleConfigBase string

var matrixExampleConfigBaseTemplate = exerrors.Must(template.New("example-config.yaml").
	Delims("$<<", ">>").
	Parse(MatrixExampleConfigBase))

func (br *BridgeMain) makeFullExampleConfig(networkExample string) string {
	var buf strings.Builder
	buf.WriteString("# Network-specific config options\n")
	buf.WriteString("network:\n")
	for _, line := range strings.Split(networkExample, "\n") {
		buf.WriteString("    ")
		buf.WriteString(line)
		buf.WriteRune('\n')
	}
	buf.WriteRune('\n')
	exerrors.PanicIfNotNil(matrixExampleConfigBaseTemplate.Execute(&buf, br.Connector.GetName()))
	return buf.String()
}
