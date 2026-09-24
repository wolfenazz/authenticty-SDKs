# Authenticity Lua SDK

## Chat identity

After login, use `getChatProfile()`, `updateChatProfile(nickname, avatarId)` to read or change the current user's chat nickname and application avatar ID. Profile calls return an identity with `id`, `nickname`, and `avatarId` (or a failure value; check the last error). Messages include `channelId`, `senderId`, and `avatarId` along with sender, content, and timestamp. Compare `senderId` with the profile `id` to identify your own messages. Preserve Unicode and line breaks in message content. The server enforces channel send cooldowns; show send errors to the user.

A complete Authenticity client SDK for Lua. It implements every endpoint exposed
by the dashboard's `/api/v1/client/*` routes, matching the behaviour of the
official C++ / C# / Python / Java / Go / Rust SDKs.

## Dependencies (all optional)

The module is fully functional with **zero** dependencies:

- **HTTP**: uses `LuaSocket` (`socket.http`) when available, otherwise falls back
  to spawning `curl` via `io.popen` (Windows ships `curl` these days).
- **JSON**: uses a `dkjson` / `json` module when available, otherwise falls back
  to a small, tolerant JSON parser/encoder bundled inside the module.

## Quick Start

```lua
local authenticity = require("authenticity")

local client = authenticity.Client.new(
    "YOUR_OWNER_ID",
    "YOUR_APP_ID",
    "https://your-domain.example/api/v1/client",
    "1.0.0",
    "YOUR_LICENSE_KEY")

if client:login() then
    print("Welcome, " .. client.session.username)
    print("Time remaining: " .. client:getRemainingTime())
else
    print("Login failed: " .. tostring(client:getLastError()))
end
```

## API Reference

All methods return a boolean (or a table/string of data) on success and set an
error retrievable via `client:getLastError()`.

| Method | Endpoint (POST unless noted) | Purpose |
| ------ | ---------------------------- | ------- |
| `login()` | `/auth/login` | License-key authentication |
| `loginWithCredentials(u, p)` | `/auth/login-user` | Username/password login |
| `register(u, p, key)` | `/auth/register` | Create a new user |
| `checkSession()` | `/auth/check` | Heartbeat / session validation |
| `checkBlacklist()` | `/auth/check-blacklist` | IP/HWID blacklist check |
| `ban(reason)` | `/auth/ban` | Self-ban (anti-tampering) |
| `getVariable(name)` | `/vars/get` | Fetch a remote variable |
| `downloadFile(fileId)` | `/files/download` | Download raw bytes |
| `downloadFileDirect(fileId)` | `/files/download` | Open URL in browser |
| `triggerWebhook(name, data)` | `/webhooks/trigger` | Trigger a webhook |
| `log(data, type)` | `/logs/add` | Send an application log |
| `getChannels()` | `/chat/channels` | List chat channels |
| `getMessages(channelId)` | `/chat/messages` (POST) | Fetch messages |
| `sendMessage(channelId, content)` | `/chat/messages` (PUT) | Send a message |

### Getters / helpers

- `getSession()` → table (`token`, `expiry`, `username`, `ip`, `hwid`, `level`, `isValid`, `updateLink`)
- `getAppData()` → table (`name`, `version`, `status`, `hwidLock`)
- `getLastError()` → last error message
- `getRemainingTime()` → `"0 Years : 0 Months : 0 Days : 12 Hours : 30 Mins"`
- `setLicenseKey(key)` → set/update the license key

The live session and app data are also exposed directly on the client as
`client.session` and `client.appData`.

### Credential management (auto-login)

```lua
-- Save
client:saveCredentials(1, "LICENSE-KEY", "", "")          -- license
client:saveCredentials(2, "", "myuser", "mypassword")     -- user/pass

-- Load
local creds = client:loadCredentials()   -- { loginType, licenseKey, username, password, isValid }
if creds.isValid then /* use creds */ end

-- Delete
client:deleteCredentials()
```

Credentials are stored in `login.json` next to the running script
(see `client:credentialsPath()`).

## Session Heartbeat

```lua
while client:checkSession() do
    -- your application loop (sleep ~15s between pings)
end
print("Session ended: " .. tostring(client:getLastError()))
```

## Working Example

See [`example.lua`](example.lua) for a runnable demo covering login, variables,
logs, chat, webhooks, and a heartbeat loop.

## Notes

- `apiUrl` must be the full base URL **including** `/api/v1/client`.
- HWID uses the same DJB2 algorithm as the other Authenticity SDKs so a user's
  hardware ID is consistent regardless of which SDK builds your client.

## Subscription entitlements

`client:getSession()` returns `subscriptionId`, `subscriptionName`, `features`, and `limits` alongside `level`. Login populates the values and `checkSession()` refreshes them. Call `client:hasFeature("export")` for a server-side feature check; denial does not invalidate the session. Create templates in Dashboard → Subscriptions and assign them to a license or directly to a user. A direct user assignment overrides the license assignment. Limits are configuration values; enforce application-specific quotas in your trusted backend.
