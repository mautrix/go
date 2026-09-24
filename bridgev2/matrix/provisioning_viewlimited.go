// Copyright (c) 2026 Killian Lelong
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package matrix

import (
	"encoding/json"
	"io"
	"net/http"

	"go.mau.fi/util/exhttp"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
)

func (prov *ProvisioningAPI) PostViewLimitedMedia(w http.ResponseWriter, r *http.Request) {
	login := prov.GetLoginForRequest(w, r)
	if login == nil {
		return
	}
	var request json.RawMessage
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
		mautrix.MBadJSON.WithMessage("Invalid media open request").Write(w)
		return
	}
	if err := prov.br.Bridge.ViewLimitedMedia(r.Context(), login, id.EventID(r.PathValue("eventID")), request); err != nil {
		RespondWithError(w, err, "Failed to open media")
		return
	}
	exhttp.WriteJSONResponse(w, http.StatusOK, struct{}{})
}
