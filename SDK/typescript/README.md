# Authenticity TypeScript SDK

## Chat identity

After login, use `await getChatProfile()`, `await updateChatProfile(nickname, avatarId)` to read or change the current user's chat nickname and application avatar ID. Profile calls return an identity with `id`, `nickname`, and `avatarId` (or a failure value; check the last error). Messages include `channelId`, `senderId`, and `avatarId` along with sender, content, and timestamp. Compare `senderId` with the profile `id` to identify your own messages. Preserve Unicode and line breaks in message content. The server enforces channel send cooldowns; show send errors to the user.

Authenticity is an auth/licensing server. This SDK provides a complete,
idiomatic, fully-typed TypeScript client for its HTTP API. It is
**dependency-free** — it uses only the global [`fetch`](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API)
API with no external packages — and mirrors the behavior and feature set of the
existing Go / Python / Java / C# SDKs in the same repository.

It works in both **Node.js** (≥ 14, which ships `fetch`) and modern **browsers**.

## Features

- License-key login, username/password login, and user registration
- Session heartbeat (`checkSession`) with expired/reason handling
- Hardware blacklist checks and session banning
- Server-side variable lookup
- File download (returns raw bytes) and direct browser download
- Webhook triggering and log reporting
- Chat channels, message reading, and message sending
- Auto-login credential persistence (`login.json` in Node, `localStorage` in the browser)
- Stable, cross-SDK machine fingerprint (HWID) generation
- Tolerant response parsing (the server may return `"true"`/`"false"` strings
  or real booleans for `success`)

## Requirements

- TypeScript 4.5+ for the type definitions, or any TypeScript target from ES2020
- Node.js 14+ (global `fetch`) or a modern browser
- No runtime dependencies

## Installation

```bash
npm install authenticity-sdk
# or, for a local checkout:
cd SDK/typescript
npm run build             # emit dist/ for package-style usage
npx tsc --noEmit          # type-check only
```

The published package contains the compiled `dist/` output and its `main`,
`types`, and `exports` entries point there. The package runs `tsc` during
`npm pack`/publishing so the release artifact is self-contained.

## Quick Start

```typescript
import { Authenticity } from "authenticity-sdk";

// apiUrl MUST already end with /api/v1/client.
const client = new Authenticity(
  "owner-id",
  "app-id",
  "https://your-domain.example/api/v1/client",
  "1.0.0",
  "YOUR_LICENSE_KEY" // optional, for license-key login
);

const ok = await client.login();
if (!ok) {
  console.log("login failed:", client.getLastError());
  process.exit(1);
}
console.log("logged in, remaining:", client.getRemainingTime());

// Heartbeat / session check.
if (!(await client.checkSession())) {
  console.log("session expired:", client.getLastError());
  process.exit(1);
}

// Read a variable.
console.log(await client.getVariable("welcomeMessage"));

// Chat.
const channels = await client.getChannels();
for (const ch of channels) {
  console.log(ch.name);
}
```

> **All network methods are `async`** and return `Promise`s because they use the
> global `fetch` API.

## Constructor

```typescript
const client = new Authenticity(ownerId, appId, apiUrl, version, licenseKey?);
```

Before login, call `checkForUpdate()` when the dashboard may require a newer
client. It returns `updateRequired`, `currentVersion`, and `updateLink`.
Chat reads use `POST /chat/messages`; `sendMessage(channelId, content)` sends
a user comment with `PUT /chat/messages`.

| Argument      | Type   | Description                                                              |
| ------------- | ------ | ------------------------------------------------------------------------ |
| `ownerId`     | string | The Authenticity owner identifier.                                       |
| `appId`       | string | The Authenticity application identifier.                                 |
| `apiUrl`      | string | Base URL that **must already end with** `/api/v1/client`.                |
| `version`     | string | The client/application version reported to the server.                   |
| `licenseKey?` | string | Optional license key used by `login()`.                                  |
