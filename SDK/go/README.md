# Authenticity Go SDK

## Chat identity

After login, use `GetChatProfile() (ChatProfile, bool)`, `UpdateChatProfile(nickname, avatarID) (ChatProfile, bool)` to read or change the current user's chat nickname and application avatar ID. Profile calls return an identity with `id`, `nickname`, and `avatarId` (or a failure value; check the last error). Messages include `channelId`, `senderId`, and `avatarId` along with sender, content, and timestamp. Compare `senderId` with the profile `id` to identify your own messages. Preserve Unicode and line breaks in message content. The server enforces channel send cooldowns; show send errors to the user.

Authenticity is an auth/licensing server. This SDK provides a dependency-light,
idiomatic Go client for its HTTP API. It mirrors the behavior and feature set of
the existing C#/C++ SDKs and the newer Python/Java SDKs.

## Features

- License-key login, username/password login, and user registration
- Session heartbeat (`CheckSession`) with expired/reason handling
- Hardware blacklist checks and session banning
- Server-side variable lookup
- File download (returns raw bytes) and direct browser download
- Webhook triggering and log reporting
- Chat channels, message reading, and message sending
- Auto-login credential persistence (`login.json` next to the executable)
- Stable, cross-SDK machine fingerprint (HWID) generation

## Requirements

- Go 1.21 or later
- No external dependencies (standard library only)

## Installation

```bash
go get github.com/authenticity/sdk-go@latest
# or, for a local checkout:
cd SDK/go
go build ./...
```

## Quick Start

```go
package main

import (
	"fmt"
	"github.com/authenticity/sdk-go/authenticity"
)

func main() {
	// APIURL MUST already end with /api/v1/client.
	client := authenticity.NewClient(
		"owner-id",
		"app-id",
        "https://your-domain.example/api/v1/client",
		"1.0.0",
	)

	if !client.LoginWithCredentials("user", "pass") {
		fmt.Println("login failed:", client.GetLastError())
		return
	}
	fmt.Println("logged in, remaining:", client.GetRemainingTime())

	// Heartbeat / session check.
	if !client.CheckSession() {
		fmt.Println("session expired:", client.GetLastError())
		return
	}

	// Read a variable.
	fmt.Println(client.GetVariable("welcomeMessage"))

	// Chat.
	for _, ch := range client.GetChannels() {
		fmt.Println(ch.Name)
	}
}
```

## Constructor

```go
client := authenticity.NewClient(ownerID, appID, apiURL, version)
```

`apiURL` must already end with `/api/v1/client` (for example
`https://your-domain.example/api/v1/client`).

## API Reference

### Authentication

| Method | Description |
| ------ | ----------- |
| `Login() bool` | Login with the configured `LicenseKey`. |
| `LoginWithCredentials(user, pass string) bool` | Login with username/password. |
| `CheckForUpdate() *UpdateInfo` | Check the dashboard version before login. |
| `Register(user, pass, licenseKey string) bool` | Create a new user account. |
| `CheckSession() bool` | Heartbeat; handles `expired`/`reason` responses. |
| `CheckBlacklist() bool` | Returns `true` when the machine is blacklisted. |
| `Ban(reason string) bool` | Report abuse; invalidates the session on success. |

### Data & Features

| Method | Description |
| ------ | ----------- |
| `GetVariable(name string) string` | Fetch a server-side variable value. |
| `DownloadFile(fileId string) ([]byte, error)` | Fetch raw file bytes. |
| `DownloadFileDirect(fileId string) bool` | Open the file URL in a browser. |
| `TriggerWebhook(name string, data map[string]interface{}) bool` | Fire a webhook. |
| `Log(data, logType string)` | Send a log entry (no-op unless session valid). |

### Chat

| Method | Description |
| ------ | ----------- |
| `GetChannels() []Channel` | List chat channels. |
| `GetMessages(channelId string) []Message` | Read messages (`"all"` for all) with POST. |
| `SendMessage(channelId, content string) bool` | Post a comment with PUT. |

### Auto-Login Credentials

| Method | Description |
| ------ | ----------- |
| `SaveCredentials(loginType int, licenseKey, username, password string) bool` | Persist to `login.json` next to the executable. |
| `LoadCredentials() SavedCredentials` | Read saved credentials. |
| `DeleteCredentials() bool` | Remove `login.json`. |

Validation rules: `LoginType 1` (license) is valid when `licenseKey` is
non-empty; `LoginType 2` (username/password) is valid when both are non-empty.

### Getters & Helpers

| Method | Description |
| ------ | ----------- |
| `SetLicenseKey(key string)` | Set the license key. |
| `GetSession() Session` | Current session state. |
| `GetAppData() AppData` | Current application metadata. |
| `GetLastError() string` | Most recent error, or `""`. |
| `GetUpdateLink() string` | Session update link (empty for logins). |
| `GetRemainingTime() string` | e.g. `"0 Years : 0 Months : 0 Days : 0 Hours : 5 Mins"`. |
| `GetHwid() string` / `GetHash() string` | Machine fingerprints. |
| `ComputeHwid() string` | Standalone HWID generation. |

## Types

- `Session{Token, Expiry, Username, IP, Hwid string; Level int; IsValid bool; UpdateLink string}`
- `AppData{Name, Version, Status string; HwidLock bool}`
- `Channel{ID, Name, CooldownUnit string; CooldownTime int}`
- `Message{ID, Sender, Content, TimeSent string}`
- `SavedCredentials{LoginType int; LicenseKey, Username, Password string; IsValid bool}`
- `UpdateInfo{UpdateRequired bool; ClientVersion, CurrentVersion, UpdateLink, AppName, AppStatus string}`


## Client-Side HTTP API

All endpoints are `POST` with `Content-Type: application/json`. Authenticated
endpoints send the token as `Authorization: Bearer <token>` **and** inside the
JSON body. The base URL already ends with `/api/v1/client`.

| Endpoint | Request body | Response |
| -------- | ------------ | -------- |
| `/auth/login` | `ownerId, appId, licenseKey, hwid, version, hash` | `success, token, expiry, username, ip, appName, appVersion, appStatus, level, hwidLock` |
| `/auth/login-user` | `ownerId, appId, username, password, hwid, version, hash` | same as login |
| `/auth/register` | `ownerId, appId, username, password, licenseKey, hwid, version, hash` | `success`, optional `message` |
| `/auth/check` | `token, appId` | `success`; on failure `expired`, `reason` |
| `/auth/check-blacklist` | `ownerId, appId, hwid` | `success` |
| `/auth/ban` | `token, appId, reason` | `success` |
| `/vars/get` | `token, appId, name` | `success, value` |
| `/files/download` | `token, appId, fileId` | `success, url` — SDK then GETs `url` for bytes |
| `/webhooks/trigger` | `token, appId, webhookName, data` | `success` |
| `/logs/add` | `token, appId, data, type` | `success` |
| `/chat/channels` | `token, appId` | `success, channels[]` |
| `/chat/messages` | `token, appId, channelId` | `success, messages[]`; PUT adds `content` → `success` |

## HWID Generation

The HWID is a stable machine fingerprint derived from the hostname and platform
machine identifiers (WMI via PowerShell on Windows, `machine-id` on Linux/macOS).
It is hashed with DJB2 (seed `5381`) followed by a second DJB2-XOR pass (seed
`0xDEADBEEF`), producing a hex string that is consistent across the C#/C++/
Python/Java/Go SDKs. Generation is best-effort and returns `"UNKNOWN_HWID"` on
total failure.
