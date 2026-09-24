# Authenticity — Ruby Client SDK

## Chat identity

After login, use `get_chat_profile`, `update_chat_profile(nickname, avatar_id)` to read or change the current user's chat nickname and application avatar ID. Profile calls return an identity with `id`, `nickname`, and `avatarId` (or a failure value; check the last error). Messages include `channelId`, `senderId`, and `avatarId` along with sender, content, and timestamp. Compare `senderId` with the profile `id` to identify your own messages. Preserve Unicode and line breaks in message content. The server enforces channel send cooldowns; show send errors to the user.

A lightweight, dependency-free **Ruby** client for the
[Authenticity] auth/licensing server.

This SDK uses **only the Ruby standard library** (`net/http`, `json`,
`openssl`, `digest`, `socket`, `uri`). There are **no external gems** and no
build step — just `require 'authenticity'`.

The client mirrors the behavior of the existing C# / C++ / Python / Go SDKs.

---

## Installation

Drop the `lib` folder into your project and require it:

```ruby
$LOAD_PATH.unshift(File.expand_path('lib', __dir__))
require 'authenticity'
```

Ruby version: 2.5+ (uses keyword arguments, casecmp, etc.).

---

## Quick start

```ruby
client = Authenticity::Client.new(
  owner_id: 'YOUR_OWNER_ID',
  app_id:   'YOUR_APP_ID',
  api_url:  'https://your-domain.example/api/v1/client',
  version:  '1.0.0',
  license_key: 'YOUR_LICENSE_KEY'
)

if client.login
  puts "Hello #{client.session['username']}!"
  puts "Remaining time: #{client.get_remaining_time}"
else
  puts "Login failed: #{client.get_last_error}"
end
```

> **Note:** `api_url` must **already end with `/api/v1/client`**. A trailing
> slash is tolerated (it is stripped internally).

---

## API Overview

All requests are `POST` (except chat message sending, which uses `PUT`, and
file downloads, which follow the returned download URL with a `GET`). Every
request sends `Content-Type: application/json`. After login, the session token
is sent **both** as an `Authorization: Bearer <token>` header **and** inside the
JSON body of every authenticated endpoint.

| Method | Endpoint | Body keys | Notes |
|--------|----------|-----------|-------|
| `login` | `/auth/login` | `ownerId, appId, licenseKey, hwid, version, hash` | License-key login |
| `login_with_credentials(user, pass)` | `/auth/login-user` | `ownerId, appId, username, password, hwid, version, hash` | Username/`password` login |
| `check_for_update` | `/app/update` | `ownerId, appId, version` | Check the dashboard version before login |
| `register(user, pass, license_key)` | `/auth/register` | `ownerId, appId, username, password, licenseKey, hwid, version, hash` | Creates an account |
| `check_session` | `/auth/check` | `token, appId` | Heartbeat; handles `expired` + `reason` |
| `check_blacklist` | `/auth/check-blacklist` | `ownerId, appId, hwid` | Returns `true` if blacklisted |
| `ban(reason)` | `/auth/ban` | `token, appId, reason` | Invalidates session on success |
| `get_variable(name)` | `/vars/get` | `token, appId, name` | Returns the variable value |
| `download_file(file_id)` | `/files/download` | `token, appId, fileId` | Returns raw bytes (`String`) via a `GET` to the download URL |
| `download_file_direct(file_id)` | `/files/download` | `token, appId, fileId` | Opens the download URL in the browser, returns `true/false` |
| `trigger_webhook(name, data)` | `/webhooks/trigger` | `token, appId, webhookName, data` | `data` is any JSON value |
| `log(data, type = "info")` | `/logs/add` | `token, appId, data, type` | Adds a log entry |
| `get_channels` | `/chat/channels` | `token, appId` | Returns array of channels |
| `get_messages(channel_id = "all")` | `/chat/messages` (**POST**) | `token, appId, channelId` | Returns array of messages |
| `send_message(channel_id, content)` | `/chat/messages` (**PUT**) | `token, appId, channelId, content` | Sends a message |

---

## Data shapes

**Session** (after a successful login)

```ruby
{
  'token' => '...',
  'expiry' => '...',
  'username' => '...',
  'ip' => '...',
  'hwid' => '...',
  'level' => 1,          # Integer
  'is_valid' => true,
  'update_link' => ''    # login responses do not include updateLink → ""
}
```

**AppData**

```ruby
{
  'name' => '...',
  'version' => '...',
  'status' => '...',
  'hwid_lock' => false
}
```

**Channel**

```ruby
{ 'id' => '...', 'name' => '...', 'cooldown_unit' => '...', 'cooldown_time' => 0 }
```

**Message**

```ruby
{ 'id' => '...', 'sender' => '...', 'content' => '...', 'time_sent' => '...' }
```


---

## Helper methods

| Method | Description |
|--------|-------------|
| `set_license_key(key)` | Set/overwrite the license key |
| `get_license_key` | Current license key |
| `set_hash(value)` | Set the request `hash` field (anti-tamper) |
| `get_session` | The session hash |
| `get_app_data` | The app-data hash |
| `get_last_error` | Last error message (`""` if none) |
| `get_update_link` | Update link (`""` if absent) |
| `get_remaining_time` | `"0 Years : 0 Months : 0 Days : 0 Hours : 0 Mins"` formatted string |
| `credentials_path` | Path to `login.json` (next to the main script `$0`) |
| `save_credentials(type, key, user, pass)` | Writes `login.json` |
| `load_credentials` | Returns `{ 'login_type', 'license_key', 'username', 'password', 'is_valid' }` |
| `delete_credentials` | Deletes `login.json` |

---

## HWID

The client computes a **stable machine fingerprint**:

1. On **Windows**, reads WMI identifiers via PowerShell
   (`Win32_Processor`, `Win32_LogicalDisk`, `Win32_BIOS`).
2. Otherwise falls back to the **hostname**.
3. The string is hashed with **DJB2 (seed 5381)** plus a **second
   DJB2-XOR pass (0xDEADBEEF)** and rendered as a hex string — deterministic
   and consistent with the C#/C++/Python/Go SDKs.

On total failure it returns the literal string `"UNKNOWN_HWID"`.


---

## HTTP behavior

- Read timeout: **30 seconds** (also used as open timeout).
- TLS with peer verification for `https://` URLs.
- `User-Agent: Authenticity SDK/1.0 (Ruby)` on every request.
- The response body is **always parsed as JSON**, even on non-2xx status codes
  (the API returns JSON error bodies with 4xx/5xx statuses).
- Network errors set `last_error` and return safe defaults (`false`, `[]`,
  `""`, `{}`).

---

## Running the example

```bash
ruby example.rb
```

Edit `example.rb` and fill in your `OWNER_ID`, `APP_ID`, and `LICENSE_KEY`
first. The example demonstrates login, heartbeat, blacklist check, variables,
chat, logs, and webhooks.

---

## Testing

A syntax check can be run with:

```bash
ruby -c lib/authenticity.rb
ruby -c example.rb
```

See `test/mock_server.rb` for a self-contained mock HTTP server (uses only the
standard library) that can be used to exercise every endpoint against a local
server without contacting the real API.

---

## License

Provided as-is; see your Authenticity agreement for terms.

## Subscription entitlements

The session hash includes `subscription_id`, `subscription_name`, `features`, and `limits` alongside `level`. Login populates the values and `check_session` refreshes them. Call `client.has_feature("export")` for a server-side feature check; denial does not invalidate the session. Create templates in Dashboard → Subscriptions and assign them to a license or directly to a user. A direct user assignment overrides the license assignment. Limits are configuration values; enforce application-specific quotas in your trusted backend.
