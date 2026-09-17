<p align="center">
  <img src="SDK/Logo.png" alt="Authenticity logo" width="180">
</p>

# Authenticity SDKs

Official client SDK examples for integrating [Authenticity](https://authenticty.vercel.app/) authentication, licensing, session validation, and application services into desktop, server, and scripting projects.

This repository contains source SDKs for multiple languages. Each SDK talks to the same Authenticity client API, so an application can use the language that best fits its runtime while keeping the same authentication flow and data model.

## What you can build

- License-key and username/password authentication
- User registration and application update checks
- Session heartbeats and license-expiry handling
- Hardware ID (HWID) binding and blacklist checks
- Remote variables and application metadata
- File downloads and direct download links
- Webhooks and application logging
- Chat channels, message history, and message sending
- Optional credential persistence for auto-login

## SDKs in this repository

| Language | Directory | Requirements | Documentation |
| --- | --- | --- | --- |
| C# | `SDK/C#/Authenticity` | .NET Framework 4.8, Visual Studio | [Open solution](SDK/C%23/Authenticity/Authenticity.sln) |
| C++ | `SDK/C++/application` | Windows, Visual Studio, C++17, WinHTTP | [C++ README](SDK/C%2B%2B/application/README.md) |
| Go | `SDK/go` | Go 1.21+ | [Go README](SDK/go/README.md) |
| Java | `SDK/java` | JDK 11+ | [Java README](SDK/java/README.md) |
| JavaScript | `SDK/javascript` | Node.js 18+ or a browser with `fetch` | [JavaScript README](SDK/javascript/README.md) |
| Lua | `SDK/lua` | Lua; LuaSocket and JSON libraries are optional | [Lua README](SDK/lua/README.md) |
| PHP | `SDK/php` | PHP 7.4+, `curl`, and `json` extensions | [PHP README](SDK/php/README.md) |
| Python | `SDK/python` | Python 3.7+ | [Python README](SDK/python/README.md) |
| Ruby | `SDK/ruby` | Ruby 2.5+ | [Ruby README](SDK/ruby/README.md) |
| Rust | `SDK/rust` | Rust 2021 toolchain | [Rust README](SDK/rust/README.md) |
| TypeScript | `SDK/typescript` | TypeScript 4.5+, Node.js 18+ or a modern browser | [TypeScript README](SDK/typescript/README.md) |

The language-specific README is the source of truth for that SDK’s exact API, build process, and platform notes.

## Quick start

1. Create an application in the [Authenticity dashboard](https://authenticty.vercel.app/).
2. Copy the application’s owner ID, application ID, and API URL.
3. Choose an SDK above and follow its README.
4. Set the API URL to the complete client base URL, including `/api/v1/client`:

   ```text
   https://your-domain.example/api/v1/client
   ```

5. Authenticate with a license key or username/password.
6. Call `checkSession()` / `check_session()` periodically while the application is running.

### Minimal flow

The method names vary by language, but the integration pattern is the same:

```text
create client(ownerId, appId, apiUrl, version [, licenseKey])
checkForUpdate()                 # optional, before login
login() or loginWithCredentials()
checkSession()                   # repeat during the authenticated session
getVariable(), downloadFile(),   # optional application features
getChannels(), sendMessage()
```

For example, the Python SDK uses the following local-checkout flow:

```bash
cd SDK/python
python example.py
```

Edit `example.py` first and provide your own application values. The example files in the other SDK directories follow the same pattern.

## API contract

The SDKs target the client API under the configured base URL. Most operations use JSON `POST` requests; chat message sending uses `PUT`, and file downloads follow the URL returned by the API.

| Operation | Endpoint | Purpose |
| --- | --- | --- |
| License login | `/auth/login` | Authenticate with a license key |
| User login | `/auth/login-user` | Authenticate with username and password |
| Registration | `/auth/register` | Create a user account using a license key |
| Update check | `/app/update` | Check whether the client must be updated |
| Session check | `/auth/check` | Validate the current session and license |
| Blacklist check | `/auth/check-blacklist` | Check the current owner/app/HWID combination |
| Remote variable | `/vars/get` | Read a server-side variable |
| File download | `/files/download` | Resolve and download an application file |
| Webhook | `/webhooks/trigger` | Trigger a configured webhook |
| Logging | `/logs/add` | Send an application log entry |
| Chat channels | `/chat/channels` | List available channels |
| Chat messages | `/chat/messages` | Read or send channel messages |
| Self-ban | `/auth/ban` | Report abuse or invalidate the current session |

After login, authenticated SDKs send the session token as a bearer token and in the request body where required by the API implementation.

## Configuration values

| Value | Description |
| --- | --- |
| `ownerId` | Authenticity account or owner identifier |
| `appId` | Authenticity application identifier from the dashboard |
| `apiUrl` | Full API base URL ending in `/api/v1/client` |
| `version` | Version of the client application being authenticated |
| `licenseKey` | Optional license key used by license-based login |

Do not commit real owner IDs, license keys, usernames, passwords, session tokens, or saved `login.json` files. Use environment variables or a platform secret store for production credentials.

## Local development

Run commands from the SDK directory you are testing:

```bash
# Go
cd SDK/go
go test ./...

# Java
cd SDK/java
# See README.md for the javac command and mock validation harness.

# Rust
cd SDK/rust
cargo test

# TypeScript
cd SDK/typescript
npm install
npm run typecheck
npm run build
```

The Java, Go, and Ruby SDKs include local validation or mock-test coverage. Examples that call the live service require valid application credentials and network access.

## Security and operational guidance

- Use HTTPS for every production API URL.
- Treat license keys and user passwords as secrets.
- Never log passwords, license keys, or session tokens.
- Store auto-login credentials only when your application has a clear, secure storage strategy; the sample `login.json` helpers are intentionally simple.
- Validate the session on a regular interval appropriate for your product. A failed heartbeat should end or restrict the authenticated session.
- Treat downloaded files and remote variables as untrusted application input.
- Handle `getLastError()` / `get_last_error()` and the equivalent method in your language so users receive actionable failure messages.

## Repository layout

```text
SDK/
├── C#/          .NET Framework / Windows example
├── C++/         Visual Studio / WinHTTP example and reusable source
├── go/          Go module and example
├── java/        Dependency-free Java client and mock test
├── javascript/  JavaScript client and Node example
├── lua/         Lua module and example
├── php/         PHP client and example
├── python/      Python standard-library client and example
├── ruby/        Ruby standard-library client and tests
├── rust/        Cargo library and example
└── typescript/  Typed client, build config, and example
```

Build output and local credentials are ignored through `SDK/.gitignore`. Before publishing a release, review generated files, examples, package metadata, and the language-specific README for the SDK you are releasing.

## Contributing

When adding or changing an SDK:

1. Keep endpoint names and request fields aligned with the client API.
2. Update that SDK’s README and example in the same change.
3. Add or update a mock test where the language supports it.
4. Run the relevant formatter, compiler, and test commands.
5. Never include real credentials in source, tests, examples, or commits.

## License and service terms

The SDK folders include their own package metadata and license declarations where applicable. Confirm the terms that apply to your Authenticity account and deployment before redistributing an SDK or shipping it in a commercial product.

## Links

- [Authenticity website and dashboard](https://authenticty.vercel.app/)
- [SDK source directory](SDK/)
