// Copyright (c) 2024 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"
	"golang.org/x/net/html"

	"maunium.net/go/mautrix/bridgev2"

	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

var CommandLogin = &FullHandler{
	Func: fnLogin,
	Name: "login",
	Help: HelpMeta{
		Section:     HelpSectionAuth,
		Description: "Log into the bridge",
		Args:        "[_flow ID_]",
	},
	RequiresLoginPermission: true,
}

func formatFlowsReply(flows []bridgev2.LoginFlow) string {
	var buf strings.Builder
	for _, flow := range flows {
		_, _ = fmt.Fprintf(&buf, "* `%s` - %s\n", flow.ID, flow.Description)
	}
	return buf.String()
}

func fnLogin(ce *Event) {
	flows := ce.Bridge.Network.GetLoginFlows()
	var chosenFlowID string
	if len(ce.Args) > 0 {
		inputFlowID := strings.ToLower(ce.Args[0])
		for _, flow := range flows {
			if flow.ID == inputFlowID {
				chosenFlowID = flow.ID
				break
			}
		}
		if chosenFlowID == "" {
			ce.Reply("Invalid login flow `%s`. Available options:\n\n%s", ce.Args[0], formatFlowsReply(flows))
			return
		}
	} else if len(flows) == 1 {
		chosenFlowID = flows[0].ID
	} else {
		ce.Reply("Please specify a login flow, e.g. `login %s`.\n\n%s", flows[0].ID, formatFlowsReply(flows))
		return
	}

	login, err := ce.Bridge.Network.CreateLogin(ce.Ctx, ce.User, chosenFlowID)
	if err != nil {
		ce.Reply("Failed to prepare login process: %v", err)
		return
	}
	nextStep, err := login.Start(ce.Ctx)
	if err != nil {
		ce.Reply("Failed to start login: %v", err)
		return
	}
	doLoginStep(ce, login, nextStep)
}

type userInputLoginCommandState struct {
	Login           bridgev2.LoginProcessUserInput
	Data            map[string]string
	RemainingFields []bridgev2.LoginInputDataField
}

func (uilcs *userInputLoginCommandState) promptNext(ce *Event) {
	field := uilcs.RemainingFields[0]
	if field.Description != "" {
		ce.Reply("Please enter your %s\n%s", field.Name, field.Description)
	} else {
		ce.Reply("Please enter your %s", field.Name)
	}
	StoreCommandState(ce.User, &CommandState{
		Next:   MinimalCommandHandlerFunc(uilcs.submitNext),
		Action: "Login",
		Meta:   uilcs,
		Cancel: uilcs.Login.Cancel,
	})
}

func (uilcs *userInputLoginCommandState) submitNext(ce *Event) {
	field := uilcs.RemainingFields[0]
	field.FillDefaultValidate()
	var err error
	uilcs.Data[field.ID], err = field.Validate(ce.RawArgs)
	if err != nil {
		ce.Reply("Invalid value: %v", err)
		return
	} else if len(uilcs.RemainingFields) > 1 {
		uilcs.RemainingFields = uilcs.RemainingFields[1:]
		uilcs.promptNext(ce)
		return
	}
	StoreCommandState(ce.User, nil)
	if nextStep, err := uilcs.Login.SubmitUserInput(ce.Ctx, uilcs.Data); err != nil {
		ce.Reply("Failed to submit input: %v", err)
	} else {
		doLoginStep(ce, uilcs.Login, nextStep)
	}
}

const qrSizePx = 512

func sendQR(ce *Event, qr string, prevEventID *id.EventID) error {
	qrData, err := qrcode.Encode(qr, qrcode.Low, qrSizePx)
	if err != nil {
		return fmt.Errorf("failed to encode QR code: %w", err)
	}
	qrMXC, qrFile, err := ce.Bot.UploadMedia(ce.Ctx, ce.RoomID, qrData, "qr.png", "image/png")
	if err != nil {
		return fmt.Errorf("failed to upload image: %w", err)
	}
	content := &event.MessageEventContent{
		MsgType:  event.MsgImage,
		FileName: "qr.png",
		URL:      qrMXC,
		File:     qrFile,

		Body:          qr,
		Format:        event.FormatHTML,
		FormattedBody: fmt.Sprintf("<pre><code>%s</code></pre>", html.EscapeString(qr)),
	}
	if *prevEventID != "" {
		content.SetEdit(*prevEventID)
	}
	newEventID, err := ce.Bot.SendMessage(ce.Ctx, ce.RoomID, event.EventMessage, &event.Content{Parsed: content}, time.Now())
	if err != nil {
		return err
	}
	if *prevEventID == "" {
		*prevEventID = newEventID.EventID
	}
	return nil
}

type contextKey int

const (
	contextKeyPrevEventID contextKey = iota
)

func doLoginDisplayAndWait(ce *Event, login bridgev2.LoginProcessDisplayAndWait, step *bridgev2.LoginStep) {
	prevEvent, ok := ce.Ctx.Value(contextKeyPrevEventID).(*id.EventID)
	if !ok {
		prevEvent = new(id.EventID)
		ce.Ctx = context.WithValue(ce.Ctx, contextKeyPrevEventID, prevEvent)
	}
	switch step.DisplayAndWaitParams.Type {
	case bridgev2.LoginDisplayTypeQR:
		err := sendQR(ce, step.DisplayAndWaitParams.Data, prevEvent)
		if err != nil {
			ce.Reply("Failed to send QR code: %v", err)
			login.Cancel()
			return
		}
	case bridgev2.LoginDisplayTypeEmoji:
		ce.ReplyAdvanced(step.DisplayAndWaitParams.Data, false, false)
	case bridgev2.LoginDisplayTypeCode:
		ce.ReplyAdvanced(fmt.Sprintf("<code>%s</code>", html.EscapeString(step.DisplayAndWaitParams.Data)), false, true)
	case bridgev2.LoginDisplayTypeNothing:
		// Do nothing
	default:
		ce.Reply("Unsupported display type %q", step.DisplayAndWaitParams.Type)
		login.Cancel()
		return
	}
	nextStep, err := login.Wait(ce.Ctx)
	// Redact the QR code, unless the next step is refreshing the code (in which case the event is just edited)
	if *prevEvent != "" && (nextStep == nil || nextStep.StepID != step.StepID) {
		_, _ = ce.Bot.SendMessage(ce.Ctx, ce.RoomID, event.EventRedaction, &event.Content{
			Parsed: &event.RedactionEventContent{
				Redacts: *prevEvent,
			},
		}, time.Now())
		*prevEvent = ""
	}
	if err != nil {
		ce.Reply("Login failed: %v", err)
		return
	}
	doLoginStep(ce, login, nextStep)
}

type cookieLoginCommandState struct {
	Login bridgev2.LoginProcessCookies
	Data  *bridgev2.LoginCookiesParams
}

func (clcs *cookieLoginCommandState) prompt(ce *Event) {
	StoreCommandState(ce.User, &CommandState{
		Next:   MinimalCommandHandlerFunc(clcs.submit),
		Action: "Login",
		Meta:   clcs,
		Cancel: clcs.Login.Cancel,
	})
}

var curlCookieRegex = regexp.MustCompile(`-H '[cC]ookie: ([^']*)'`)

func missingKeys(required []string, data map[string]string) (missing []string) {
	for _, requiredKey := range required {
		if _, ok := data[requiredKey]; !ok {
			missing = append(missing, requiredKey)
		}
	}
	return
}

func (clcs *cookieLoginCommandState) submit(ce *Event) {
	ce.Redact()

	cookies := make(map[string]string)
	if strings.HasPrefix(strings.TrimSpace(ce.RawArgs), "curl") {
		if len(clcs.Data.LocalStorageKeys) > 0 || len(clcs.Data.SpecialKeys) > 0 {
			ce.Reply("Special keys and localStorage keys can't be extracted from curl commands - please provide the data as JSON instead")
			return
		}
		cookieHeader := curlCookieRegex.FindStringSubmatch(ce.RawArgs)
		if len(cookieHeader) != 2 {
			ce.Reply("Couldn't find `-H 'Cookie: ...'` in curl command")
			return
		}
		parsed := (&http.Request{Header: http.Header{"Cookie": {cookieHeader[1]}}}).Cookies()
		for _, cookie := range parsed {
			cookies[cookie.Name] = cookie.Value
		}
	} else {
		err := json.Unmarshal([]byte(ce.RawArgs), &cookies)
		if err != nil {
			ce.Reply("Failed to parse input as JSON: %v", err)
			return
		}
	}
	missingCookies := missingKeys(clcs.Data.CookieKeys, cookies)
	if len(missingCookies) > 0 {
		ce.Reply("Missing required cookies: %+v", missingCookies)
		return
	}
	missingLocalStorage := missingKeys(clcs.Data.LocalStorageKeys, cookies)
	if len(missingLocalStorage) > 0 {
		ce.Reply("Missing required localStorage keys: %+v", missingLocalStorage)
		return
	}
	missingSpecial := missingKeys(clcs.Data.SpecialKeys, cookies)
	if len(missingSpecial) > 0 {
		ce.Reply("Missing required special keys: %+v", missingSpecial)
		return
	}
	StoreCommandState(ce.User, nil)
	nextStep, err := clcs.Login.SubmitCookies(ce.Ctx, cookies)
	if err != nil {
		ce.Reply("Login failed: %v", err)
	}
	doLoginStep(ce, clcs.Login, nextStep)
}

func doLoginStep(ce *Event, login bridgev2.LoginProcess, step *bridgev2.LoginStep) {
	ce.Reply(step.Instructions)

	switch step.Type {
	case bridgev2.LoginStepTypeDisplayAndWait:
		doLoginDisplayAndWait(ce, login.(bridgev2.LoginProcessDisplayAndWait), step)
	case bridgev2.LoginStepTypeCookies:
		(&cookieLoginCommandState{
			Login: login.(bridgev2.LoginProcessCookies),
			Data:  step.CookiesParams,
		}).prompt(ce)
	case bridgev2.LoginStepTypeUserInput:
		(&userInputLoginCommandState{
			Login:           login.(bridgev2.LoginProcessUserInput),
			RemainingFields: step.UserInputParams.Fields,
			Data:            make(map[string]string),
		}).promptNext(ce)
	case bridgev2.LoginStepTypeComplete:
		// Nothing to do other than instructions
	default:
		panic(fmt.Errorf("unknown login step type %q", step.Type))
	}
}

var CommandListLogins = &FullHandler{
	Func: fnListLogins,
	Name: "list-logins",
	Help: HelpMeta{
		Section:     HelpSectionAuth,
		Description: "List your logins",
	},
	RequiresLoginPermission: true,
}

func fnListLogins(ce *Event) {
	logins := ce.User.GetFormattedUserLogins()
	if len(logins) == 0 {
		ce.Reply("You're not logged in")
	} else {
		ce.Reply("%s", logins)
	}
}

var CommandLogout = &FullHandler{
	Func: fnLogout,
	Name: "logout",
	Help: HelpMeta{
		Section:     HelpSectionAuth,
		Description: "Log out of the bridge",
		Args:        "<_login ID_>",
	},
}

func fnLogout(ce *Event) {
	if len(ce.Args) == 0 {
		ce.Reply("Usage: `$cmdprefix logout <login ID>`\n\nYour logins:\n\n%s", ce.User.GetFormattedUserLogins())
		return
	}
	login := ce.Bridge.GetCachedUserLoginByID(networkid.UserLoginID(ce.Args[0]))
	if login == nil || login.UserMXID != ce.User.MXID {
		ce.Reply("Login `%s` not found", ce.Args[0])
		return
	}
	login.Logout(ce.Ctx)
	ce.Reply("Logged out")
}

var CommandSetPreferredLogin = &FullHandler{
	Func:    fnSetPreferredLogin,
	Name:    "set-preferred-login",
	Aliases: []string{"prefer"},
	Help: HelpMeta{
		Section:     HelpSectionAuth,
		Description: "Set the preferred login ID for sending messages to this portal (only relevant when logged into multiple accounts via the bridge)",
		Args:        "<_login ID_>",
	},
	RequiresPortal:          true,
	RequiresLoginPermission: true,
}

func fnSetPreferredLogin(ce *Event) {
	if len(ce.Args) == 0 {
		ce.Reply("Usage: `$cmdprefix set-preferred-login <login ID>`\n\nYour logins:\n\n%s", ce.User.GetFormattedUserLogins())
		return
	}
	login := ce.Bridge.GetCachedUserLoginByID(networkid.UserLoginID(ce.Args[0]))
	if login == nil || login.UserMXID != ce.User.MXID {
		ce.Reply("Login `%s` not found", ce.Args[0])
		return
	}
	err := login.MarkAsPreferredIn(ce.Ctx, ce.Portal)
	if err != nil {
		ce.Reply("Failed to set preferred login: %v", err)
	} else {
		ce.Reply("Preferred login set")
	}
}
