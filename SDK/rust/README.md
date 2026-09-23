# Authenticity Rust SDK

## Chat identity

After login, use `get_chat_profile()`, `update_chat_profile(nickname, avatar_id)` to read or change the current user's chat nickname and application avatar ID. Profile calls return an identity with `id`, `nickname`, and `avatarId` (or a failure value; check the last error). Messages include `channelId`, `senderId`, and `avatarId` along with sender, content, and timestamp. Compare `senderId` with the profile `id` to identify your own messages. Preserve Unicode and line breaks in message content. The server enforces channel send cooldowns; show send errors to the user.

Rust client library for the Authenticity authentication and licensing API.
The crate provides a blocking client suitable for desktop applications, tools,
and other synchronous Rust programs.

## Requirements

- Rust 2021 toolchain
- Network access to the configured Authenticity API
- An application configured in the [Authenticity dashboard](https://authenticty.vercel.app/)

## Installation

For a local checkout:

```bash
cd SDK/rust
cargo build
cargo test
```

To use the source from another Cargo project, add the local path while
developing:

```toml
[dependencies]
authenticity = { path = "../path/to/authenticty-SDKs/SDK/rust" }
```

The crate currently depends on `reqwest`, `serde`, `serde_json`, and `chrono`.

## Quick start

```rust
use authenticity::Client;

fn main() {
    let mut client = Client::new(
        "YOUR_OWNER_ID",
        "YOUR_APP_ID",
        "https://your-domain.example/api/v1/client",
        "1.0.0",
    );
    client.set_license_key("YOUR_LICENSE_KEY");

    if !client.login() {
        eprintln!("Login failed: {}", client.get_last_error());
        return;
    }

    println!("Welcome, {}", client.get_session().username);
    println!("Time remaining: {}", client.get_remaining_time());

    if !client.check_session() {
        eprintln!("Session ended: {}", client.get_last_error());
    }
}
```

`api_url` must include the `/api/v1/client` suffix. Use
`login_with_credentials(username, password)` for username/password login.

## API overview

Authentication and session methods:

- `login()` and `login_with_credentials(...)`
- `register(...)`
- `check_for_update()`
- `check_session()` and `check_blacklist()`
- `get_session()`, `get_app_data()`, `get_last_error()`

Application features:

- `get_variable(...)`
- `download_file(...)` and `download_file_direct(...)`
- `trigger_webhook(...)` and `log(...)`
- `get_channels()`, `get_messages(...)`, and `send_message(...)`
- Credential helpers: `save_credentials(...)`, `load_credentials()`, and
  `delete_credentials()`

See [`src/lib.rs`](src/lib.rs) and [`examples/example.rs`](examples/example.rs)
for the complete public API and a runnable example.

## Security notes

- Use HTTPS in production.
- Do not commit owner IDs, license keys, passwords, or session tokens.
- Keep the blocking calls off your UI thread when integrating into a graphical
  application.
- Treat downloaded files and remote variables as untrusted input.
