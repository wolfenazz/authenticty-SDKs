# Authenticity JavaScript SDK

## Chat identity

After login, use `await getChatProfile()`, `await updateChatProfile(nickname, avatarId)` to read or change the current user's chat nickname and application avatar ID. Profile calls return an identity with `id`, `nickname`, and `avatarId` (or a failure value; check the last error). Messages include `channelId`, `senderId`, and `avatarId` along with sender, content, and timestamp. Compare `senderId` with the profile `id` to identify your own messages. Preserve Unicode and line breaks in message content. The server enforces channel send cooldowns; show send errors to the user.

Authenticity is an auth/licensing server. This SDK provides a complete,
dependency-free JavaScript client (Node `>=18` and modern browsers, CommonJS)
for its HTTP API. It mirrors the behavior and feature set of the existing
C#/C++ SDKs and the newer Go/Python/Java/Ruby/TypeScript SDKs.

## Features

- License-key login, username/password login, and user registration
- Session heartbeat (`checkSession`) with expired/reason handling
- Hardware blacklist checks and session banning
- Server-side variable lookup
- File download (raw bytes) and direct browser download
- Webhook triggering and log reporting
- Chat channels, message reading, and message sending
- Auto-login credential persistence (`login.json` in Node, `localStorage` in browsers)
- Stable, cross-SDK machine fingerprint (HWID) generation

## Requirements

- Node.js 18+ (for browsers: must support global `fetch`; uses `localStorage`)
- No external dependencies — global `fetch` and Node built-ins only

## Installation

```bash
npm install authenticity-sdk
# or, using the local checkout directly:
#   const { Authenticity } = require('./path/to/SDK/javascript/src/Authenticity');
```

## Quick Start

```js
const { Authenticity } = require('./src/Authenticity');

// API_URL MUST already end with /api/v1/client.
const client = new Authenticity(
  'owner-id',
  'app-id',
  'https://your-domain.example/api/v1/client',
  '1.0.0'
);

async function main() {
  if (!(await client.loginWithCredentials('user', 'pass'))) {
    console.log('login failed:', client.getLastError());
    return;
  }
  console.log('remaining:', client.getRemainingTime());

  // Heartbeat / session check.
  if (!(await client.checkSession())) {
    console.log('session expired:', client.getLastError());
    return;
  }

  // Remote variable.
  console.log(await client.getVariable('welcomeMessage'));

  // Chat.
  const channels = await client.getChannels();
  for (const ch of channels) console.log(ch.name);
}

main();
```

## Constructor

```js
const client = new Authenticity(ownerId, appId, apiUrl, version, licenseKey?);
```

`apiUrl` must already end with `/api/v1/client` (for example
`https://your-domain.example/api/v1/client`). All methods that hit the network
return Promises.

## API Reference

### Authentication (all `async`)

| Method | Description |
| ------ | ----------- |
| `login()` | Login with the configured license key. |
| `loginWithCredentials(user, pass)` | Login with username/password. |
| `checkForUpdate()` | Check the dashboard version before login. |
| `register(user, pass, licenseKey)` | Create a new user account. |
| `checkSession()` | Heartbeat; handles `expired`/`reason` responses. |
| `checkBlacklist()` | Resolves `true` when the machine is blacklisted. |

### Getters & Helpers

| Method | Description |
| ------ | ----------- |
| `setLicenseKey(key)` | Set the license key. |
| `getSession()` | Current session state. |
| `getAppData()` | Current application metadata. |
| `getLastError()` | Most recent error, or `""`. |
| `getUpdateLink()` | Session update link (empty for logins). |
| `getRemainingTime()` | e.g. `"0 Years : 0 Months : 0 Days : 0 Hours : 5 Mins"`. |
| `getHwid()` / `getHash()` | Machine fingerprints. |
| `Authenticity.computeHwid()` (`static`) | Standalone HWID generation. |

## Types / Shapes

- `Session { token, expiry, username, ip, hwid, level, isValid, updateLink }`
- `AppData { name, version, status, hwidLock }`
- `Channel { id, name, cooldownUnit, cooldownTime }`
- `Message { id, sender, content, timeSent }`
- `SavedCredentials { loginType, licenseKey, username, password, isValid }`

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
| `/chat/messages` | `token, appId, channelId` | `success, messages[]`; adding `content` → `success` |

**Note:** the server returns `success` as a string `"true"`/`"false"` in many
responses. This SDK tolerantly treats `"true"`, `true`, and `1` as success, and
`"false"`, `missing`, and `null` as failure.

## HWID Generation

The HWID is a stable machine fingerprint derived from the hostname and platform
machine identifiers (WMI via PowerShell on Windows, `machine-id` on
Linux/macOS, or best-effort `navigator` info in browsers). It is hashed with
DJB2 (seed `5381`) followed by a second DJB2-XOR pass (seed `0xDEADBEEF`),
producing a hex string consistent across the C#/C++/Python/Java/Go SDKs.
Generation is best-effort and returns `"UNKNOWN_HWID"` on total failure.

| `ban(reason)` | Report abuse; invalidates the session on success. |

### Data & Features (`async`)

| Method | Description |
| ------ | ----------- |
| `getVariable(name)` | Fetch a server-side variable value. |
| `downloadFile(fileId)` | Fetch raw file bytes (`ArrayBuffer`). |
| `downloadFileDirect(fileId)` | Open the file URL in a browser / print it in Node. |
| `triggerWebhook(name, data)` | Fire a webhook. |
| `log(data, type)` | Send a log entry; resolves to `true` only when accepted. |

### Chat (`async`)

| Method | Description |
| ------ | ----------- |
| `getChannels()` | List chat channels. |
| `getMessages(channelId)` | Read messages (`"all"` for all) with POST. |
| `sendMessage(channelId, content)` | Post a comment with PUT. |

### Auto-Login Credentials (synchronous)

| Method | Description |
| ------ | ----------- |
| `saveCredentials(loginType, licenseKey, username, password)` | Persist auth data. |
| `loadCredentials()` | Read saved credentials. |
| `deleteCredentials()` | Remove saved credentials. |

Validation: `loginType 1` (license) is valid when `licenseKey` is non-empty;
`loginType 2` (username/password) is valid when both are non-empty.
