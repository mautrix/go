package gomatrix

// ReqRegister is the JSON request for http://matrix.org/docs/spec/client_server/r0.2.0.html#post-matrix-client-r0-register
type ReqRegister struct {
	Username                 string      `json:"username,omitempty"`
	BindEmail                bool        `json:"bind_email,omitempty"`
	Password                 string      `json:"password,omitempty"`
	DeviceID                 string      `json:"device_id,omitempty"`
	InitialDeviceDisplayName string      `json:"initial_device_display_name"`
	Auth                     interface{} `json:"auth,omitempty"`
}

// ReqLogin is the JSON request for http://matrix.org/docs/spec/client_server/r0.2.0.html#post-matrix-client-r0-login
type ReqLogin struct {
	Type                     string `json:"type"`
	Password                 string `json:"password,omitempty"`
	Medium                   string `json:"medium,omitempty"`
	User                     string `json:"user,omitempty"`
	Address                  string `json:"address,omitempty"`
	Token                    string `json:"token,omitempty"`
	DeviceID                 string `json:"device_id,omitempty"`
	InitialDeviceDisplayName string `json:"initial_device_display_name,omitempty"`
}
