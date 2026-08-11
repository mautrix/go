package continuwuityadmin

import (
	"maunium.net/go/mautrix"
)

// Client is a wrapper for the mautrix.Client struct that includes methods for accessing the Continuwuity admin API.
type Client struct {
	Client *mautrix.Client
}

func (cli *Client) BuildAdminURL(path ...any) string {
	return cli.Client.BuildURL(mautrix.ContinuwuityAdminURLPath(path))
}
