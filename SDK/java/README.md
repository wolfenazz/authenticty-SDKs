# Authenticity Java SDK

A complete, **dependency-free** (JDK standard library only) client for the
Authenticity authentication system. It implements every endpoint exposed by the
dashboard's `/api/v1/client/*` routes, matching the behaviour of the official
C++ / C# / Python SDKs.

## Requirements

- Java 11 or newer (built and tested with Java 17)
- No third-party libraries (uses `java.net.http.HttpClient`)

## Features

- **Auth**: license key, username/password, and registration
- **Hardware ID Lock**: stable per-machine HWID for session binding
- **Session Management**: `checkSession()` heartbeat with expiry handling
- **Remote Variables**, **File Downloads** (bytes or browser), **Webhooks**
- **Logging**, **Chat** (channels, messages, send), **Auto-Login** (`login.json`)
- **Security**: executable hash verification and self-ban support

## Layout

```
SDK/java/
├── src/main/java/com/authenticity/
│   ├── Authenticity.java      # Main client (all endpoints)
│   ├── Json.java              # Minimal dependency-free JSON parser
│   ├── Session.java           # Session model
│   ├── AppData.java           # App metadata model
│   ├── SavedCredentials.java  # Auto-login credentials model
│   ├── Hwid.java              # Hardware-ID generation
│   └── Hash.java              # Executable MD5 hash
└── src/test/java/SDKTest.java # Mock HTTP validation harness
```

## Build & Run (no build tool required)

```bash
cd SDK/java
# PowerShell:
javac -d out ($(Get-ChildItem -Recurse -Filter '*.java' src).FullName)
# Linux/macOS:
# mkdir -p out && find src -name "*.java" -print0 | xargs -0 javac -d out

# Run the mock validation harness (all assertions should PASS)
java -cp out SDKTest
```

The layout also opens directly as an IntelliJ IDEA module (the `.idea` folder is
already present).

## Quick Start

```java
import com.authenticity.Authenticity;

Authenticity client = new Authenticity(
    "YOUR_OWNER_ID",
    "YOUR_APP_ID",
    "https://your-domain.example/api/v1/client",
    "1.0.0",
    "YOUR_LICENSE_KEY");

if (client.login()) {
    System.out.println("Welcome, " + client.getSession().getUsername());
    System.out.println("Time remaining: " + client.getRemainingTime());
} else {
    System.out.println("Login failed: " + client.getLastError());
}
```

## Authentication Methods

```java
// 1. License key
Authenticity c1 = new Authenticity(ownerId, appId, apiUrl, version, licenseKey);
if (c1.login()) { /* authenticated */ }

// 2. Username / password
Authenticity c2 = new Authenticity(ownerId, appId, apiUrl, version);
if (c2.loginWithCredentials("myuser", "mypassword")) { /* authenticated */ }

// 3. Registration
Authenticity c3 = new Authenticity(ownerId, appId, apiUrl, version);
if (c3.register("newuser", "password123", "LICENSE-KEY")) { /* registered */ }
```

## API Reference

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

- `getSession()` → `Session` (`getToken`, `getExpiry`, `getUsername`, `getIp`, `getHwid`, `getLevel`, `isValid`, `getUpdateLink`)
- `getAppData()` → `AppData` (`getName`, `getVersion`, `getStatus`, `isHwidLock`)
- `getLastError()` → last error message
- `getRemainingTime()` → `"0 Years : 0 Months : 0 Days : 12 Hours : 30 Mins"`
- `setLicenseKey(key)` → set/update the license key

### Credential management (auto-login)

```java
// Save
Authenticity.saveCredentials(1, "LICENSE-KEY", "", "");              // license
Authenticity.saveCredentials(2, "", "myuser", "mypassword");         // user/pass

// Load
SavedCredentials creds = Authenticity.loadCredentials();  // isValid(), getLicenseKey(), ...
if (creds.isValid()) { /* use creds */ }

// Delete
Authenticity.deleteCredentials();
```

Credentials are stored in `login.json` in the current working directory
(see `Authenticity.credentialsPath()`).

## Session Heartbeat

```java
import java.util.concurrent.TimeUnit;

while (client.checkSession()) {
    // your application loop
    TimeUnit.SECONDS.sleep(15);
}
```

When `checkSession()` returns `false`, inspect `getLastError()` for the reason
(license expired, session expired, or banned).

## Validation

The included [`SDKTest.java`](src/test/java/SDKTest.java) spins up a local mock
HTTP server and verifies every endpoint is hit with the correct method and JSON
body keys. All 15 assertions pass (see "Build & Run").

## Notes

- `apiUrl` must be the full base URL **including** `/api/v1/client`.
- HWID uses the same DJB2 algorithm as the other SDKs so a user's hardware ID is
  consistent regardless of which SDK your client is built with.
