// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package bridgev2

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
}

func formatFlowsReply(flows []LoginFlow) string {
	var buf strings.Builder
	for _, flow := range flows {
		_, _ = fmt.Fprintf(&buf, "* `%s` - %s\n", flow.ID, flow.Description)
	}
	return buf.String()
}

func fnLogin(ce *CommandEvent) {
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
	Login           LoginProcessUserInput
	Data            map[string]string
	RemainingFields []LoginInputDataField
}

func (uilcs *userInputLoginCommandState) promptNext(ce *CommandEvent) {
	// TODO reply prompting field
	ce.User.CommandState.Store(&CommandState{
		Next:   MinimalCommandHandlerFunc(uilcs.submitNext),
		Action: "Login",
		Meta:   uilcs,
		Cancel: uilcs.Login.Cancel,
	})
}

func (uilcs *userInputLoginCommandState) submitNext(ce *CommandEvent) {
	field := uilcs.RemainingFields[0]
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
	ce.User.CommandState.Store(nil)
	if nextStep, err := uilcs.Login.SubmitUserInput(ce.Ctx, uilcs.Data); err != nil {
		ce.Reply("Failed to submit input: %v", err)
	} else {
		doLoginStep(ce, uilcs.Login, nextStep)
	}
}

const qrSizePx = 512

func sendQR(ce *CommandEvent, qr string, prevEventID *id.EventID) error {
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

func doLoginDisplayAndWait(ce *CommandEvent, login LoginProcessDisplayAndWait, step *LoginStep) {
	prevEvent, ok := ce.Ctx.Value(contextKeyPrevEventID).(*id.EventID)
	if !ok {
		prevEvent = new(id.EventID)
		ce.Ctx = context.WithValue(ce.Ctx, contextKeyPrevEventID, prevEvent)
	}
	switch step.DisplayAndWaitParams.Type {
	case LoginDisplayTypeQR:
		err := sendQR(ce, step.DisplayAndWaitParams.Data, prevEvent)
		if err != nil {
			ce.Reply("Failed to send QR code: %v", err)
			login.Cancel()
			return
		}
	case LoginDisplayTypeEmoji:
		ce.ReplyAdvanced(step.DisplayAndWaitParams.Data, false, false)
	case LoginDisplayTypeCode:
		ce.ReplyAdvanced(fmt.Sprintf("<code>%s</code>", html.EscapeString(step.DisplayAndWaitParams.Data)), false, true)
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
	Login LoginProcessCookies
	Data  *LoginCookiesParams
}

func (clcs *cookieLoginCommandState) prompt(ce *CommandEvent) {
	ce.User.CommandState.Store(&CommandState{
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

func (clcs *cookieLoginCommandState) submit(ce *CommandEvent) {
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
	ce.User.CommandState.Store(nil)
	nextStep, err := clcs.Login.SubmitCookies(ce.Ctx, cookies)
	if err != nil {
		ce.Reply("Login failed: %v", err)
	}
	doLoginStep(ce, clcs.Login, nextStep)
}

func doLoginStep(ce *CommandEvent, login LoginProcess, step *LoginStep) {
	ce.Reply(step.Instructions)

	switch step.Type {
	case LoginStepTypeDisplayAndWait:
		doLoginDisplayAndWait(ce, login.(LoginProcessDisplayAndWait), step)
	case LoginStepTypeCookies:
		(&cookieLoginCommandState{
			Login: login.(LoginProcessCookies),
			Data:  step.CookiesParams,
		}).prompt(ce)
	case LoginStepTypeUserInput:
		(&userInputLoginCommandState{
			Login:           login.(LoginProcessUserInput),
			RemainingFields: step.UserInputParams.Fields,
			Data:            make(map[string]string),
		}).promptNext(ce)
	case LoginStepTypeComplete:
		// Nothing to do other than instructions
	default:
		panic(fmt.Errorf("unknown login step type %q", step.Type))
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

func getUserLogins(user *User) string {
	user.Bridge.cacheLock.Lock()
	logins := make([]string, len(user.logins))
	for key := range user.logins {
		logins = append(logins, fmt.Sprintf("* `%s`", key))
	}
	user.Bridge.cacheLock.Unlock()
	return strings.Join(logins, "\n")
}

func fnLogout(ce *CommandEvent) {
	if len(ce.Args) == 0 {
		ce.Reply("Usage: `$cmdprefix logout <login ID>`\n\nYour logins:\n\n%s", getUserLogins(ce.User))
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
	RequiresPortal: true,
}

func fnSetPreferredLogin(ce *CommandEvent) {
	if len(ce.Args) == 0 {
		ce.Reply("Usage: `$cmdprefix set-preferred-login <login ID>`\n\nYour logins:\n\n%s", getUserLogins(ce.User))
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
