package commands

import (
	"strings"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/provisionutil"
	"maunium.net/go/mautrix/id"
)

var CommandSetProfile = &FullHandler{
	Func: fnSetProfile,
	Name: "set-profile",
	Help: HelpMeta{
		Section:     HelpSectionAuth,
		Description: "Update a remote account's name or avatar",
		Args:        "<_login ID_> <name|avatar> <_value_>",
	},
	RequiresLogin: true,
	NetworkAPI:    NetworkAPIImplements[bridgev2.ProfileUpdatingNetworkAPI],
}

func fnSetProfile(ce *Event) {
	if len(ce.Args) < 3 {
		ce.Reply("Usage: `$cmdprefix set-profile <login ID> <name|avatar> <value>`\n\nYour logins:\n\n%s", ce.User.GetFormattedUserLogins())
		return
	}
	login := ce.Bridge.GetCachedUserLoginByID(networkid.UserLoginID(ce.Args[0]))
	if login == nil || login.UserMXID != ce.User.MXID {
		ce.Reply("Login `%s` not found", ce.Args[0])
		return
	}
	var params bridgev2.ProfileUpdateParams
	switch ce.Args[1] {
	case "name":
		name := strings.Join(ce.Args[2:], " ")
		params.Name = &name
	case "avatar":
		if len(ce.Args) != 3 {
			ce.Reply("Usage: `$cmdprefix set-profile <login ID> avatar <mxc URI>`")
			return
		}
		avatar := id.ContentURIString(ce.Args[2])
		params.Avatar = &avatar
	default:
		ce.Reply("Profile field must be `name` or `avatar`")
		return
	}
	if err := provisionutil.UpdateProfile(ce.Ctx, login, &params); err != nil {
		ce.Reply("Failed to update profile: %s", err)
		return
	}
	ce.Reply("Profile updated")
}
