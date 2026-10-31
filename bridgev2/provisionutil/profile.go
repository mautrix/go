package provisionutil

import (
	"context"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
)

func UpdateProfile(ctx context.Context, login *bridgev2.UserLogin, params *bridgev2.ProfileUpdateParams) error {
	if login.Client == nil || !login.Client.IsLoggedIn() {
		return bridgev2.ErrNotLoggedIn
	}
	api, ok := login.Client.(bridgev2.ProfileUpdatingNetworkAPI)
	if !ok {
		return bridgev2.RespError(mautrix.MUnrecognized.WithMessage("This bridge does not support updating profiles"))
	}
	if params == nil || params.Name == nil && params.Avatar == nil {
		return bridgev2.RespError(mautrix.MInvalidParam.WithMessage("A name or avatar is required"))
	}
	if params.Avatar != nil && *params.Avatar != "" {
		if _, err := params.Avatar.Parse(); err != nil {
			return bridgev2.RespError(mautrix.MInvalidParam.WithMessage("Avatar must be an MXC URI"))
		}
	}
	return api.UpdateProfile(ctx, params)
}
