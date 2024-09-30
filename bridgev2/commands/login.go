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
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/skip2/go-qrcode"
	"go.mau.fi/util/curl"
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
		ce.Args = ce.Args[1:]
		for _, flow := range flows {
			if flow.ID == inputFlowID {
				chosenFlowID = flow.ID
				break
			}
		}
		if chosenFlowID == "" {
			ce.Reply("Invalid login flow `%s`. Available options:\n\n%s", inputFlowID, formatFlowsReply(flows))
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

	nextStep = checkLoginCommandDirectParams(ce, login, nextStep)
	if nextStep != nil {
		doLoginStep(ce, login, nextStep)
	}
}

func checkLoginCommandDirectParams(ce *Event, login bridgev2.LoginProcess, nextStep *bridgev2.LoginStep) *bridgev2.LoginStep {
	if len(ce.Args) == 0 {
		return nextStep
	}
	var ok bool
	defer func() {
		if !ok {
			login.Cancel()
		}
	}()
	var err error
	switch nextStep.Type {
	case bridgev2.LoginStepTypeDisplayAndWait:
		ce.Reply("Invalid extra parameters for display and wait login step")
		return nil
	case bridgev2.LoginStepTypeUserInput:
		if len(ce.Args) != len(nextStep.UserInputParams.Fields) {
			ce.Reply("Invalid number of extra parameters (expected 0 or %d, got %d)", len(nextStep.UserInputParams.Fields), len(ce.Args))
			return nil
		}
		input := make(map[string]string)
		for i, param := range nextStep.UserInputParams.Fields {
			param.FillDefaultValidate()
			input[param.ID], err = param.Validate(ce.Args[i])
			if err != nil {
				ce.Reply("Invalid value for %s: %v", param.Name, err)
				return nil
			}
		}
		nextStep, err = login.(bridgev2.LoginProcessUserInput).SubmitUserInput(ce.Ctx, input)
	case bridgev2.LoginStepTypeCookies:
		if len(ce.Args) != len(nextStep.CookiesParams.Fields) {
			ce.Reply("Invalid number of extra parameters (expected 0 or %d, got %d)", len(nextStep.CookiesParams.Fields), len(ce.Args))
			return nil
		}
		input := make(map[string]string)
		for i, param := range nextStep.CookiesParams.Fields {
			val := maybeURLDecodeCookie(ce.Args[i], &param)
			if match, _ := regexp.MatchString(param.Pattern, val); !match {
				ce.Reply("Invalid value for %s: doesn't match regex `%s`", param.ID, param.Pattern)
				return nil
			}
			input[param.ID] = val
		}
		nextStep, err = login.(bridgev2.LoginProcessCookies).SubmitCookies(ce.Ctx, input)
	}
	if err != nil {
		ce.Reply("Failed to submit input: %v", err)
		return nil
	}
	ok = true
	return nextStep
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
	if field.Type == bridgev2.LoginInputFieldTypePassword {
		ce.Redact()
	}
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
	newEventID, err := ce.Bot.SendMessage(ce.Ctx, ce.RoomID, event.EventMessage, &event.Content{Parsed: content}, nil)
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
		}, nil)
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
	ce.Reply("Login URL: <%s>", clcs.Data.URL)
	StoreCommandState(ce.User, &CommandState{
		Next:   MinimalCommandHandlerFunc(clcs.submit),
		Action: "Login",
		Meta:   clcs,
		Cancel: clcs.Login.Cancel,
	})
}

func (clcs *cookieLoginCommandState) submit(ce *Event) {
	ce.Redact()

	cookiesInput := make(map[string]string)
	if strings.HasPrefix(strings.TrimSpace(ce.RawArgs), "curl") {
		parsed, err := curl.Parse(ce.RawArgs)
		if err != nil {
			ce.Reply("Failed to parse curl: %v", err)
			return
		}
		reqCookies := make(map[string]string)
		for _, cookie := range parsed.Cookies() {
			reqCookies[cookie.Name], err = url.QueryUnescape(cookie.Value)
			if err != nil {
				ce.Reply("Failed to parse cookie %s: %v", cookie.Name, err)
				return
			}
		}
		var missingKeys, unsupportedKeys []string
		for _, field := range clcs.Data.Fields {
			var value string
			var supported bool
			for _, src := range field.Sources {
				switch src.Type {
				case bridgev2.LoginCookieTypeCookie:
					supported = true
					value = reqCookies[src.Name]
				case bridgev2.LoginCookieTypeRequestHeader:
					supported = true
					value = parsed.Header.Get(src.Name)
				case bridgev2.LoginCookieTypeRequestBody:
					supported = true
					switch {
					case parsed.MultipartForm != nil:
						values, ok := parsed.MultipartForm.Value[src.Name]
						if ok && len(values) > 0 {
							value = values[0]
						}
					case parsed.ParsedJSON != nil:
						untypedValue, ok := parsed.ParsedJSON[src.Name]
						if ok {
							value = fmt.Sprintf("%v", untypedValue)
						}
					}
				}
				if value != "" {
					cookiesInput[field.ID] = value
					break
				}
			}
			if value == "" && field.Required {
				if supported {
					missingKeys = append(missingKeys, field.ID)
				} else {
					unsupportedKeys = append(unsupportedKeys, field.ID)
				}
			}
		}
		if len(unsupportedKeys) > 0 {
			ce.Reply("Some keys can't be extracted from a cURL request: %+v\n\nPlease provide a JSON object instead.", unsupportedKeys)
			return
		} else if len(missingKeys) > 0 {
			ce.Reply("Missing some keys: %+v", missingKeys)
			return
		}
	} else {
		err := json.Unmarshal([]byte(ce.RawArgs), &cookiesInput)
		if err != nil {
			ce.Reply("Failed to parse input as JSON: %v", err)
			return
		}
		for _, field := range clcs.Data.Fields {
			val, ok := cookiesInput[field.ID]
			if ok {
				cookiesInput[field.ID] = maybeURLDecodeCookie(val, &field)
			}
		}
	}
	var missingKeys []string
	for _, field := range clcs.Data.Fields {
		val, ok := cookiesInput[field.ID]
		if !ok && field.Required {
			missingKeys = append(missingKeys, field.ID)
		}
		if match, _ := regexp.MatchString(field.Pattern, val); !match {
			ce.Reply("Invalid value for %s: doesn't match regex `%s`", field.ID, field.Pattern)
			return
		}
	}
	if len(missingKeys) > 0 {
		ce.Reply("Missing some keys: %+v", missingKeys)
		return
	}
	StoreCommandState(ce.User, nil)
	nextStep, err := clcs.Login.SubmitCookies(ce.Ctx, cookiesInput)
	if err != nil {
		ce.Reply("Login failed: %v", err)
		return
	}
	doLoginStep(ce, clcs.Login, nextStep)
}

func maybeURLDecodeCookie(val string, field *bridgev2.LoginCookieField) string {
	if val == "" {
		return val
	}
	isCookie := slices.ContainsFunc(field.Sources, func(src bridgev2.LoginCookieFieldSource) bool {
		return src.Type == bridgev2.LoginCookieTypeCookie
	})
	if !isCookie {
		return val
	}
	match, _ := regexp.MatchString(field.Pattern, val)
	if !match {
		return val
	}
	decoded, err := url.QueryUnescape(val)
	if err != nil {
		return val
	}
	return decoded
}

func doLoginStep(ce *Event, login bridgev2.LoginProcess, step *bridgev2.LoginStep) {
	if step.Instructions != "" {
		ce.Reply(step.Instructions)
	}

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
