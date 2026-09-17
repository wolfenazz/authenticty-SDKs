// Package authenticity is a client SDK for the Authenticity auth/licensing
// server. It mirrors the behavior and feature set of the existing C#/C++
// SDKs as well as the newer Python and Java SDKs.
//
// The server exposes its client HTTP API under `/api/v1/client`. The base URL
// provided to the client must already end with that path.
package authenticity

import (
	"time"
)

// Default values used throughout the SDK.
const (
	// defaultTimeOut is the HTTP client timeout used for requests.
	defaultTimeOut = 30 * time.Second

	// userAgent is sent with every request.
	userAgent = "Authenticity SDK/1.0 (Go)"

	// LoginTypeLicense is the auto-login mode where a license key is used.
	LoginTypeLicense = 1
	// LoginTypeCredentials is the auto-login mode where username/password are used.
	LoginTypeCredentials = 2

	// loginJSONFile is the name of the file holding saved credentials.
	loginJSONFile = "login.json"

	// hwidUnknown is returned by HWID generation on total failure.
	hwidUnknown = "UNKNOWN_HWID"
)

// API endpoint paths, all relative to the base URL which already ends with
// `/api/v1/client`.
const (
	endpointLogin          = "/auth/login"
	endpointLoginUser      = "/auth/login-user"
	endpointRegister       = "/auth/register"
	endpointCheck          = "/auth/check"
	endpointCheckBlacklist = "/auth/check-blacklist"
	endpointBan            = "/auth/ban"
	endpointVarsGet        = "/vars/get"
	endpointFilesDownload  = "/files/download"
	endpointWebhook        = "/webhooks/trigger"
	endpointLogsAdd        = "/logs/add"
	endpointChatChannels   = "/chat/channels"
	endpointChatMessages   = "/chat/messages"
	endpointAppUpdate      = "/app/update"
)
