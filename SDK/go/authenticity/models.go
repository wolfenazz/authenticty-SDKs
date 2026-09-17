package authenticity

// AppData holds the application metadata returned by a successful login.
type AppData struct {
	// Name is the application name.
	Name string
	// Version is the application version.
	Version string
	// Status is the application status string.
	Status string
	// HwidLock indicates whether the license is locked to a single machine.
	HwidLock bool
}

// UpdateInfo is the result of a pre-login application version check.
type UpdateInfo struct {
	UpdateRequired bool
	ClientVersion  string
	CurrentVersion string
	UpdateLink     string
	AppName        string
	AppStatus      string
}

// Session holds the authentication state established after a successful login.
type Session struct {
	// Token is the bearer token used to authenticate subsequent requests.
	Token string
	// Expiry is the human-readable session/license expiry string from the server.
	Expiry string
	// Username is the username of the authenticated user.
	Username string
	// IP is the client IP address reported by the server.
	IP string
	// Hwid is the hardware ID reported by the server.
	Hwid string
	// Level is the access level granted by the server.
	Level int
	// IsValid is true while the session is considered valid.
	IsValid bool
	// UpdateLink holds an optional update/download link. Login responses do not
	// include it; this field tolerates its absence and is generally empty.
	UpdateLink string
}

// Channel describes a chat channel returned by the chats endpoint.
type Channel struct {
	// ID is the channel identifier.
	ID string
	// Name is the readable channel name.
	Name string
	// CooldownUnit is the unit used for message cooldown, if any.
	CooldownUnit string
	// CooldownTime is the cooldown duration value.
	CooldownTime int
}

// Message is a single chat message.
type Message struct {
	// ID is the message identifier.
	ID string
	// Sender is the username of the sender.
	Sender string
	// Content is the message body.
	Content string
	// TimeSent is the timestamp string reported by the server.
	TimeSent string
}

// SavedCredentials is the persisted auto-login entry stored in login.json.
type SavedCredentials struct {
	// LoginType indicates the login mode: 1 = license key, 2 = username/password.
	LoginType int `json:"loginType"`
	// LicenseKey is used when LoginType == 1.
	LicenseKey string `json:"licenseKey"`
	// Username is used when LoginType == 2.
	Username string `json:"username"`
	// Password is used when LoginType == 2.
	Password string `json:"password"`
	// IsValid reports whether the stored set is considered usable.
	IsValid bool `json:"isValid"`
}
