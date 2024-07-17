package event

import "maunium.net/go/mautrix/id"

type BeeperPerMessageProfile struct {
	ID          string               `json:"id"`
	Displayname string               `json:"displayname,omitempty"`
	AvatarURL   *id.ContentURIString `json:"avatar_url,omitempty"`
	AvatarFile  *EncryptedFileInfo   `json:"avatar_file,omitempty"`
}
