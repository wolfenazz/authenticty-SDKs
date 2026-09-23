# Authenticity Python SDK

## Chat identity

After login, use `get_chat_profile()`, `update_chat_profile(nickname, avatar_id)` to read or change the current user's chat nickname and application avatar ID. Profile calls return an identity with `id`, `nickname`, and `avatarId` (or a failure value; check the last error). Messages include `channelId`, `senderId`, and `avatarId` along with sender, content, and timestamp. Compare `senderId` with the profile `id` to identify your own messages. Preserve Unicode and line breaks in message content. The server enforces channel send cooldowns; show send errors to the user.

A complete, **dependency-free** (Python standard library only) client for the
Authenticity authentication system. It implements every endpoint exposed by the
dashboard's `/api/v1/client/*` routes, matching the behaviour of the official
C++ and C# SDKs.

## Features

- **Multiple Authentication Methods**: license key, username/password, and user registration
- **Hardware ID Lock**: stable per-machine hardware ID for session binding
- **Session Management**: `check_session()` heartbeat with detailed expiry handling
- **License Validation**: precise time-remaining calculation
- **Remote Variables**: fetch configuration values from the server
- **File Downloads**: resolve and download files (raw bytes or open in browser)
- **Webhooks**: trigger named webhooks with custom data
- **Logging**: send application logs to the central dashboard
- **Chat**: list channels, fetch messages, send messages
- **Auto-Login**: save/reuse credentials via `login.json`
- **Security**: executable hash verification and self-ban support

## Requirements

- Python 3.7 or newer
- No third-party packages required

## Quick Start

```python
from Authenticity import Authenticity

client = Authenticity(
    owner_id="YOUR_OWNER_ID",
    app_id="YOUR_APP_ID",
    api_url="https://your-domain.example/api/v1/client",
    version="1.0.0",
    license_key="YOUR_LICENSE_KEY",
)

if client.login():
    session = client.get_session()
    print("Welcome,", session["username"])
    print("Time remaining:", client.get_remaining_time())
else:
    print("Login failed:", client.get_last_error())
```

## Authentication Methods

### 1. License key

```python
client = Authenticity(owner_id, app_id, api_url, version, license_key)
if client.login():
    # authenticated
```

### 2. Username / password

```python
client = Authenticity(owner_id, app_id, api_url, version)
if client.login_with_credentials("myuser", "mypassword"):
    # authenticated
```

### 3. Registration

```python
client = Authenticity(owner_id, app_id, api_url, version)
if client.register("newuser", "password123", "LICENSE-KEY"):
    # registered; manage login from here
```

## API Reference

All methods return `True`/useful data on success and store the error in
`get_last_error()`.

| Method | Endpoint (POST unless noted) | Purpose |
| ------ | ---------------------------- | ------- |
| `login()` | `/auth/login` | License-key authentication |
| `login_with_credentials(u, p)` | `/auth/login-user` | Username/password login |
| `check_for_update()` | `/app/update` | Check the dashboard version before login |
| `register(u, p, key)` | `/auth/register` | Create a new user |
| `check_session()` | `/auth/check` | Heartbeat / session validation |
| `check_blacklist()` | `/auth/check-blacklist` | IP/HWID blacklist check |
| `ban(reason)` | `/auth/ban` | Self-ban (anti-tampering) |
| `get_variable(name)` | `/vars/get` | Fetch a remote variable |
| `download_file(file_id)` | `/files/download` | Download raw bytes |
| `download_file_direct(file_id)` | `/files/download` | Open URL in browser |
| `trigger_webhook(name, data)` | `/webhooks/trigger` | Trigger a webhook |
| `log(data, type)` | `/logs/add` | Send an application log |
| `get_channels()` | `/chat/channels` | List chat channels |
| `get_messages(channel_id)` | `/chat/messages` (POST) | Fetch messages |
| `send_message(channel_id, content)` | `/chat/messages` (PUT) | Send a message |

### Getters / helpers

- `get_session()` → dict with `token`, `expiry`, `username`, `ip`, `hwid`, `level`, `is_valid`, `update_link`
- `get_app_data()` → dict with `name`, `version`, `status`, `hwid_lock`
- `get_last_error()` → last error message
- `get_remaining_time()` → `"0 Years : 0 Months : 0 Days : 12 Hours : 30 Mins"`
- `set_license_key(key)` → set/update the license key

Call `check_for_update()` before login when old clients must be blocked. It
returns `update_required`, `current_version`, and `update_link`.

### Credential management (auto-login)

```python
# Save
Authenticity.save_credentials(1, license_key="KEY")              # license
Authenticity.save_credentials(2, username="u", password="p")     # user/pass

# Load directly
from Authenticity import SavedCredentials
creds = Authenticity.load_credentials()          # SavedCredentials dict
if creds["is_valid"]:
    # use creds["license_key"] or creds["username"]/["password"]

# Delete
Authenticity.delete_credentials()
```

Credentials are stored in `login.json` next to your script (see
`Authenticity.credentials_path()`).

## Session Heartbeat

Keep the session alive by calling `check_session()` on an interval. When it
returns `False`, check `get_last_error()` for the reason (e.g. license expired,
session expired, or banned).

```python
import time

while client.check_session():
    # your application loop
    time.sleep(15)
```

## Working Example

See [`example.py`](example.py) for a full, runnable demo of every feature,
including auto-login, chat, variables, logs and a heartbeat loop.

## Notes

- The SDK uses only the Python standard library (`urllib`, `json`, `hashlib`).
- On Windows the hardware ID is gathered via a WMI query (CPU ID, volume serial,
  BIOS) and hashed with the same DJB2 algorithm as the C#/C++ SDKs so a user's
  HWID is consistent across languages.
- Set `API_URL` to your full base URL *including* `/api/v1/client`.
