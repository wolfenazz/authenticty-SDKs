//! Authenticity auth/licensing client SDK for Rust.
//!
//! It talks to the client HTTP API under `/api/v1/client`.
//!
//! All authenticated touch points are HTTP `application/json` requests. After
//! a successful login a session token is stored and is sent both as an
//! `Authorization: Bearer <token>` header *and* inside the JSON body of every
//! authenticated endpoint.
//!
//! # Response parsing
//!
//! The server returns the `success` field as the **string** `"true"` / `"false"`
//! in most responses (and as a real boolean in a few), so every boolean field
//! is read with [`bool_field`], which tolerates strings, booleans and 1/0.
//! The login `expiry` is an ISO-8601 timestamp (e.g. `2026-08-26T12:00:00.000Z`)
//! or `"Never"`, so [`parse_timestamp`] accepts both ISO-8601 and Unix epochs
//! (seconds or milliseconds).

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use reqwest::blocking::Client as HttpClient;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Public model types
// ---------------------------------------------------------------------------

/// A session produced by a successful login.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Session {
    pub token: String,
    pub expiry: String,
    pub username: String,
    pub ip: String,
    pub hwid: String,
    pub level: i32,
    pub is_valid: bool,
    pub update_link: String,
}

/// Metadata about the connected application returned at login time.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppData {
    pub name: String,
    pub version: String,
    pub status: String,
    pub hwid_lock: bool,
}

/// Result of a pre-login application version check.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub update_required: bool,
    pub client_version: String,
    pub current_version: String,
    pub update_link: String,
    pub app_name: String,
    pub app_status: String,
}

/// A chat channel.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Channel {
    pub id: String,
    pub name: String,
    pub cooldown_unit: String,
    pub cooldown_time: i32,
    /// Catch-all for any extra fields the server may return.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// A chat message.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    #[serde(rename = "channelId", default)]
    pub channel_id: String,
    #[serde(rename = "senderId", default)]
    pub sender_id: String,
    pub sender: String,
    #[serde(rename = "avatarId", default)]
    pub avatar_id: String,
    pub content: String,
    #[serde(rename = "timeSent", alias = "time_sent")]
    pub time_sent: String,
}

/// The current user's chat identity.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChatProfile {
    #[serde(rename = "profileId")]
    pub id: String,
    pub nickname: String,
    #[serde(rename = "avatarId")]
    pub avatar_id: String,
}

/// Credentials loaded from / persisted to `login.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SavedCredentials {
    pub login_type: i32,
    pub license_key: String,
    pub username: String,
    pub password: String,
    pub is_valid: bool,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// The main Authenticity client.
///
/// `api_url` must already end with `/api/v1/client`, e.g.
/// `https://your-domain.example/api/v1/client`.
#[derive(Debug, Clone)]
pub struct Client {
    owner_id: String,
    app_id: String,
    api_url: String,
    version: String,
    license_key: String,
    session: Session,
    app_data: AppData,
    hwid: String,
    hash: String,
    last_error: String,
    http: HttpClient,
}

impl Client {
    /// Create a new client.
    ///
    /// `api_url` ends with `/api/v1/client`. The machine fingerprint (`hwid`)
    /// and a deterministic session `hash` are computed automatically.
    pub fn new(owner_id: &str, app_id: &str, api_url: &str, version: &str) -> Self {
        let hwid = get_hwid();
        let hash = format!("{:08x}", djb2_xor(format!("{}{}", app_id, hwid).as_str()));
        Client {
            owner_id: owner_id.to_string(),
            app_id: app_id.to_string(),
            api_url: api_url.trim_end_matches('/').to_string(),
            version: version.to_string(),
            license_key: String::new(),
            session: Session::default(),
            app_data: AppData::default(),
            hwid,
            hash,
            last_error: String::new(),
            http: HttpClient::builder()
                .timeout(Duration::from_secs(30))
                .user_agent("Authenticity SDK/1.0 (Rust)")
                .build()
                .expect("failed to build HTTP client"),
        }
    }

    // ---- Getters / setters ------------------------------------------------

    pub fn set_license_key(&mut self, key: &str) {
        self.license_key = key.to_string();
    }

    pub fn get_session(&self) -> &Session {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut Session {
        &mut self.session
    }

    pub fn get_app_data(&self) -> &AppData {
        &self.app_data
    }

    pub fn get_last_error(&self) -> &str {
        &self.last_error
    }

    pub fn get_update_link(&self) -> &str {
        &self.session.update_link
    }

    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }

    pub fn app_id(&self) -> &str {
        &self.app_id
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn hwid(&self) -> &str {
        &self.hwid
    }

    /// A human readable remaining-time string derived from `expiry`, e.g.
    /// `"0 Years : 0 Months : 0 Days : 0 Hours : 0 Mins"`.
    pub fn get_remaining_time(&self) -> String {
        remaining_time(&self.session.expiry)
    }

    // ---- Low level HTTP ----------------------------------------------------

    /// Perform an authenticated POST and deserialize the reply as JSON.
    fn post(&mut self, path: &str, body: HashMap<String, serde_json::Value>) -> serde_json::Value {
        let url = format!("{}{}", self.api_url, path);
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if !self.session.token.is_empty() {
            let bearer = format!("Bearer {}", self.session.token);
            if let Ok(v) = HeaderValue::from_str(&bearer) {
                headers.insert("Authorization", v);
            }
        }

        match self.http.post(&url).headers(headers).json(&body).send() {
            Ok(resp) => match resp.json::<serde_json::Value>() {
                Ok(v) => v,
                Err(e) => {
                    self.last_error = format!("failed to parse response JSON: {e}");
                    serde_json::Value::Null
                }
            },
            Err(e) => {
                self.last_error = format!("request failed: {e}");
                serde_json::Value::Null
            }
        }
    }

    /// Perform a raw GET (used for file downloads) and return the bytes.
    fn get_bytes(&mut self, url: &str) -> Option<Vec<u8>> {
        match self.http.get(url).send() {
            Ok(resp) => match resp.bytes() {
                Ok(b) => Some(b.to_vec()),
                Err(e) => {
                    self.last_error = format!("download read failed: {e}");
                    None
                }
            },
            Err(e) => {
                self.last_error = format!("download request failed: {e}");
                None
            }
        }
    }

    // ---- Auth ---------------------------------------------------------------

    /// Login with the stored license key.
    pub fn login(&mut self) -> bool {
        let key = self.license_key.clone();
        self.login_with_key(&key)
    }

    /// Login using a specific license key.
    fn login_with_key(&mut self, license_key: &str) -> bool {
        let mut body = HashMap::new();
        body.insert("ownerId".into(), self.owner_id.clone().into());
        body.insert("appId".into(), self.app_id.clone().into());
        body.insert("licenseKey".into(), license_key.into());
        body.insert("hwid".into(), self.hwid.clone().into());
        body.insert("version".into(), self.version.clone().into());
        body.insert("hash".into(), self.hash.clone().into());

        let resp = self.post("/auth/login", body);
        self.handle_login_response(resp)
    }

    /// Login with username + password.
    pub fn login_with_credentials(&mut self, username: &str, password: &str) -> bool {
        let mut body = HashMap::new();
        body.insert("ownerId".into(), self.owner_id.clone().into());
        body.insert("appId".into(), self.app_id.clone().into());
        body.insert("username".into(), username.into());
        body.insert("password".into(), password.into());
        body.insert("hwid".into(), self.hwid.clone().into());
        body.insert("version".into(), self.version.clone().into());
        body.insert("hash".into(), self.hash.clone().into());

        let resp = self.post("/auth/login-user", body);
        self.handle_login_response(resp)
    }

    /// Check for a server update before login. Returns None on failure.
    pub fn check_for_update(&mut self) -> Option<UpdateInfo> {
        let mut body = HashMap::new();
        body.insert("ownerId".into(), self.owner_id.clone().into());
        body.insert("appId".into(), self.app_id.clone().into());
        body.insert("version".into(), self.version.clone().into());
        let resp = self.post("/app/update", body);
        if !bool_field(resp.get("success")) {
            self.show_error(&resp);
            return None;
        }
        Some(UpdateInfo {
            update_required: bool_field(resp.get("updateRequired")),
            client_version: {
                let value = str_field(&resp, "clientVersion");
                if value.is_empty() {
                    self.version.clone()
                } else {
                    value
                }
            },
            current_version: str_field(&resp, "currentVersion"),
            update_link: str_field(&resp, "updateLink"),
            app_name: str_field(&resp, "appName"),
            app_status: str_field(&resp, "appStatus"),
        })
    }

    /// Process a login-shaped response and populate the session.
    fn handle_login_response(&mut self, resp: serde_json::Value) -> bool {
        let success = bool_field(resp.get("success"));
        if success {
            let token = str_field(&resp, "token");
            if token.is_empty() {
                self.session.is_valid = false;
                self.session.update_link = str_field(&resp, "updateLink");
                self.last_error =
                    "authenticity: login response did not include a session token".into();
                return false;
            }
            self.last_error.clear();
            self.session.token = token;
            self.session.expiry = str_field(&resp, "expiry");
            self.session.username = str_field(&resp, "username");
            self.session.ip = str_field(&resp, "ip");
            let response_hwid = str_field(&resp, "hwid");
            self.session.hwid = if response_hwid.is_empty() {
                self.hwid.clone()
            } else {
                response_hwid
            };
            self.session.level = resp.get("level").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            self.session.is_valid = true;
            // login responses do not include updateLink; tolerate absence.
            self.session.update_link = str_field(&resp, "updateLink");

            self.app_data.name = str_field(&resp, "appName");
            self.app_data.version = str_field(&resp, "appVersion");
            self.app_data.status = str_field(&resp, "appStatus");
            self.app_data.hwid_lock = bool_field(resp.get("hwidLock"));
        } else {
            self.session.is_valid = false;
            self.session.update_link = str_field(&resp, "updateLink");
            self.show_error(&resp);
        }
        success
    }

    /// Register a new user account.
    pub fn register(&mut self, username: &str, password: &str, license_key: &str) -> bool {
        let mut body = HashMap::new();
        body.insert("ownerId".into(), self.owner_id.clone().into());
        body.insert("appId".into(), self.app_id.clone().into());
        body.insert("username".into(), username.into());
        body.insert("password".into(), password.into());
        body.insert("licenseKey".into(), license_key.into());
        body.insert("hwid".into(), self.hwid.clone().into());
        body.insert("version".into(), self.version.clone().into());
        body.insert("hash".into(), self.hash.clone().into());

        let resp = self.post("/auth/register", body);
        let ok = bool_field(resp.get("success"));
        if ok {
            self.last_error.clear();
        } else if let Some(m) = resp.get("message").and_then(|v| v.as_str()) {
            self.last_error = m.to_string();
        } else {
            self.show_error(&resp);
        }
        ok
    }

    /// Session heartbeat / validation. Returns true while the session is valid.
    pub fn check_session(&mut self) -> bool {
        if self.session.token.is_empty() {
            self.last_error = "no active session".to_string();
            return false;
        }
        let mut body = HashMap::new();
        body.insert("token".into(), self.session.token.clone().into());
        body.insert("appId".into(), self.app_id.clone().into());
        body.insert("hwid".into(), self.hwid.clone().into());

        let resp = self.post("/auth/check", body);
        let ok = bool_field(resp.get("success"));
        if ok {
            self.last_error.clear();
            return true;
        }

        let expired = bool_field(resp.get("expired"));
        let reason = {
            let value = str_field(&resp, "reason");
            if value.is_empty() {
                str_field(&resp, "message")
            } else {
                value
            }
        };
        self.last_error = if reason.is_empty() {
            "session check failed".to_string()
        } else {
            reason.clone()
        };
        if reason.contains("Session expired") || expired {
            self.session.is_valid = false;
            self.session.token = String::new();
            self.session.expiry = String::new();
        }
        false
    }

    /// Check whether the current hardware id is blacklisted. Returns `true` if
    /// the HWID *is* blacklisted.
    pub fn check_blacklist(&mut self) -> bool {
        let mut body = HashMap::new();
        body.insert("ownerId".into(), self.owner_id.clone().into());
        body.insert("appId".into(), self.app_id.clone().into());
        body.insert("hwid".into(), self.hwid.clone().into());

        let resp = self.post("/auth/check-blacklist", body);
        let ok = bool_field(resp.get("success"));
        if ok {
            self.last_error.clear();
            return false; // not blacklisted
        }
        self.show_error(&resp);
        true // blacklisted
    }

    /// Ban the current session. Invalidates the session on success.
    pub fn ban(&mut self, reason: &str) -> bool {
        if self.session.token.is_empty() {
            self.last_error = "no active session".to_string();
            return false;
        }
        let mut body = HashMap::new();
        body.insert("token".into(), self.session.token.clone().into());
        body.insert("appId".into(), self.app_id.clone().into());
        body.insert("reason".into(), reason.into());

        let resp = self.post("/auth/ban", body);
        let ok = bool_field(resp.get("success"));
        if ok {
            self.last_error.clear();
            self.session.token = String::new();
            self.session.is_valid = false;
        } else {
            self.show_error(&resp);
        }
        ok
    }

    // ---- Vars ---------------------------------------------------------------

    /// Fetch the value of a named variable. Returns an empty string on failure.
    pub fn get_variable(&mut self, name: &str) -> String {
        if self.session.token.is_empty() {
            self.last_error = "no active session".to_string();
            return String::new();
        }
        let mut body = HashMap::new();
        body.insert("token".into(), self.session.token.clone().into());
        body.insert("appId".into(), self.app_id.clone().into());
        body.insert("name".into(), name.into());

        let resp = self.post("/vars/get", body);
        if bool_field(resp.get("success")) {
            self.last_error.clear();
            str_field(&resp, "value")
        } else {
            self.show_error(&resp);
            String::new()
        }
    }

    // ---- Files ---------------------------------------------------------------

    /// Resolve the download URL for a file and fetch its raw bytes.
    pub fn download_file(&mut self, file_id: &str) -> Vec<u8> {
        if self.session.token.is_empty() {
            self.last_error = "no active session".to_string();
            return Vec::new();
        }
        let mut body = HashMap::new();
        body.insert("token".into(), self.session.token.clone().into());
        body.insert("appId".into(), self.app_id.clone().into());
        body.insert("fileId".into(), file_id.into());

        let resp = self.post("/files/download", body);
        if !bool_field(resp.get("success")) {
            self.show_error(&resp);
            return Vec::new();
        }
        let url = {
            let value = str_field(&resp, "url");
            if value.is_empty() {
                str_field(&resp, "downloadUrl")
            } else {
                value
            }
        };
        if url.is_empty() {
            self.last_error = "download url missing".to_string();
            return Vec::new();
        }
        self.get_bytes(&url).unwrap_or_default()
    }

    /// Resolve the download URL and open it in the default browser.
    pub fn download_file_direct(&mut self, file_id: &str) -> bool {
        if self.session.token.is_empty() {
            self.last_error = "no active session".to_string();
            return false;
        }
        let mut body = HashMap::new();
        body.insert("token".into(), self.session.token.clone().into());
        body.insert("appId".into(), self.app_id.clone().into());
        body.insert("fileId".into(), file_id.into());

        let resp = self.post("/files/download", body);
        if !bool_field(resp.get("success")) {
            self.show_error(&resp);
            return false;
        }
        let url = {
            let value = str_field(&resp, "url");
            if value.is_empty() {
                str_field(&resp, "downloadUrl")
            } else {
                value
            }
        };
        if url.is_empty() {
            self.last_error = "download url missing".to_string();
            return false;
        }
        open_in_browser(&url)
    }

    // ---- Webhooks ------------------------------------------------------------

    /// Trigger a webhook.
    pub fn trigger_webhook(&mut self, name: &str, data: serde_json::Value) -> bool {
        if self.session.token.is_empty() {
            self.last_error = "no active session".to_string();
            return false;
        }
        let mut body = HashMap::new();
        body.insert("token".into(), self.session.token.clone().into());
        body.insert("appId".into(), self.app_id.clone().into());
        body.insert("webhookName".into(), name.into());
        let webhook_data = match data {
            serde_json::Value::String(value) => value,
            other => other.to_string(),
        };
        body.insert("data".into(), webhook_data.into());

        let resp = self.post("/webhooks/trigger", body);
        let ok = bool_field(resp.get("success"));
        if ok {
            self.last_error.clear();
        } else {
            self.show_error(&resp);
        }
        ok
    }

    // ---- Logs ----------------------------------------------------------------

    /// Add a log entry. `log_type` defaults to "info" when empty.
    pub fn log(&mut self, data: &str, log_type: &str) -> bool {
        if self.session.token.is_empty() {
            self.last_error = "no active session".to_string();
            return false;
        }
        let mut body = HashMap::new();
        body.insert("token".into(), self.session.token.clone().into());
        body.insert("appId".into(), self.app_id.clone().into());
        body.insert("data".into(), data.into());
        body.insert(
            "type".into(),
            (if log_type.is_empty() {
                "info"
            } else {
                log_type
            })
            .into(),
        );

        let resp = self.post("/logs/add", body);
        let ok = bool_field(resp.get("success"));
        if ok {
            self.last_error.clear();
        } else {
            self.show_error(&resp);
        }
        ok
    }

    // ---- Chat ----------------------------------------------------------------

    /// Fetch all chat channels.
    pub fn get_channels(&mut self) -> Vec<Channel> {
        if self.session.token.is_empty() {
            self.last_error = "no active session".to_string();
            return Vec::new();
        }
        let mut body = HashMap::new();
        body.insert("token".into(), self.session.token.clone().into());
        body.insert("appId".into(), self.app_id.clone().into());

        let resp = self.post("/chat/channels", body);
        if !bool_field(resp.get("success")) {
            self.show_error(&resp);
            return Vec::new();
        }
        resp.get("channels")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|c| serde_json::from_value::<Channel>(c.clone()).ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Fetch messages for a channel (pass "all" to get every channel's).
    pub fn get_messages(&mut self, channel_id: &str) -> Vec<Message> {
        if self.session.token.is_empty() {
            self.last_error = "no active session".to_string();
            return Vec::new();
        }
        let mut body = HashMap::new();
        body.insert("token".into(), self.session.token.clone().into());
        body.insert("appId".into(), self.app_id.clone().into());
        body.insert("channelId".into(), channel_id.into());

        let resp = self.post("/chat/messages", body);
        if !bool_field(resp.get("success")) {
            self.show_error(&resp);
            return Vec::new();
        }
        resp.get("messages")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| serde_json::from_value::<Message>(m.clone()).ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Send a message to a channel (PUT).
    pub fn send_message(&mut self, channel_id: &str, content: &str) -> bool {
        if self.session.token.is_empty() {
            self.last_error = "no active session".to_string();
            return false;
        }
        let url = format!("{}{}", self.api_url, "/chat/messages");
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if !self.session.token.is_empty() {
            let bearer = format!("Bearer {}", self.session.token);
            if let Ok(v) = HeaderValue::from_str(&bearer) {
                headers.insert("Authorization", v);
            }
        }

        let mut body: HashMap<String, serde_json::Value> = HashMap::new();
        body.insert("token".into(), self.session.token.clone().into());
        body.insert("appId".into(), self.app_id.clone().into());
        body.insert("channelId".into(), channel_id.into());
        body.insert("content".into(), content.into());

        let resp = match self.http.put(&url).headers(headers).json(&body).send() {
            Ok(r) => r
                .json::<serde_json::Value>()
                .unwrap_or(serde_json::Value::Null),
            Err(e) => {
                self.last_error = format!("request failed: {e}");
                return false;
            }
        };
        let ok = bool_field(resp.get("success"));
        if ok {
            self.last_error.clear();
        } else {
            self.show_error(&resp);
        }
        ok
    }

    /// Read the current user's chat nickname and avatar.
    pub fn get_chat_profile(&mut self) -> Option<ChatProfile> {
        if self.session.token.is_empty() {
            self.last_error = "no active session".to_string();
            return None;
        }
        let mut body = HashMap::new();
        body.insert("token".into(), self.session.token.clone().into());
        body.insert("appId".into(), self.app_id.clone().into());
        let resp = self.post("/chat/profile", body);
        self.parse_chat_profile(resp)
    }

    /// Update the current user's chat nickname and application avatar ID.
    pub fn update_chat_profile(&mut self, nickname: &str, avatar_id: &str) -> Option<ChatProfile> {
        if self.session.token.is_empty() {
            self.last_error = "no active session".to_string();
            return None;
        }
        let mut body: HashMap<String, serde_json::Value> = HashMap::new();
        body.insert("token".into(), self.session.token.clone().into());
        body.insert("appId".into(), self.app_id.clone().into());
        body.insert("nickname".into(), nickname.into());
        body.insert("avatarId".into(), avatar_id.into());
        let url = format!("{}/chat/profile", self.api_url);
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Ok(v) = HeaderValue::from_str(&format!("Bearer {}", self.session.token)) {
            headers.insert("Authorization", v);
        }
        let resp = match self.http.put(&url).headers(headers).json(&body).send() {
            Ok(r) => r
                .json::<serde_json::Value>()
                .unwrap_or(serde_json::Value::Null),
            Err(e) => {
                self.last_error = format!("request failed: {e}");
                return None;
            }
        };
        self.parse_chat_profile(resp)
    }

    fn parse_chat_profile(&mut self, resp: serde_json::Value) -> Option<ChatProfile> {
        if !bool_field(resp.get("success")) {
            self.show_error(&resp);
            return None;
        }
        match serde_json::from_value::<ChatProfile>(resp) {
            Ok(profile) => {
                self.last_error.clear();
                Some(profile)
            }
            Err(e) => {
                self.last_error = format!("invalid chat profile response: {e}");
                None
            }
        }
    }

    // ---- Credential auto-login ------------------------------------------------

    /// Persist credentials to `login.json` next to the executable.
    pub fn save_credentials(
        &mut self,
        login_type: i32,
        license_key: &str,
        username: &str,
        password: &str,
    ) -> bool {
        let creds = SavedCredentials {
            login_type,
            license_key: license_key.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            is_valid: (login_type == 1 && !license_key.is_empty())
                || (login_type == 2 && !username.is_empty() && !password.is_empty()),
        };
        let path = login_json_path();
        let json = match serde_json::to_string_pretty(&creds) {
            Ok(j) => j,
            Err(e) => {
                self.last_error = format!("serialize credentials failed: {e}");
                return false;
            }
        };
        match std::fs::write(&path, json) {
            Ok(_) => {
                self.last_error.clear();
                true
            }
            Err(e) => {
                self.last_error = format!("write credentials failed: {e}");
                false
            }
        }
    }

    /// Load credentials from `login.json`. On success it also attempts an
    /// automatic login with the stored credentials.
    pub fn load_credentials(&mut self) -> SavedCredentials {
        let path = login_json_path();
        match std::fs::read_to_string(&path) {
            Ok(s) => match serde_json::from_str::<SavedCredentials>(&s) {
                Ok(mut c) => {
                    c.is_valid = (c.login_type == 1 && !c.license_key.is_empty())
                        || (c.login_type == 2 && !c.username.is_empty() && !c.password.is_empty());
                    if !c.is_valid {
                        self.last_error = "stored credentials invalid".to_string();
                        return c;
                    }
                    let ok = match c.login_type {
                        1 => self.login_with_key(c.license_key.trim()),
                        2 => self.login_with_credentials(c.username.trim(), c.password.trim()),
                        _ => {
                            self.last_error = "unknown login_type".to_string();
                            false
                        }
                    };
                    c.is_valid = ok;
                    c
                }
                Err(e) => {
                    self.last_error = format!("parse credentials failed: {e}");
                    SavedCredentials::default()
                }
            },
            Err(e) => {
                self.last_error = format!("read credentials failed: {e}");
                SavedCredentials::default()
            }
        }
    }

    /// Remove `login.json`.
    pub fn delete_credentials(&mut self) -> bool {
        let path = login_json_path();
        match std::fs::remove_file(&path) {
            Ok(_) => {
                self.last_error.clear();
                true
            }
            Err(e) => {
                self.last_error = format!("delete credentials failed: {e}");
                false
            }
        }
    }

    // ---- Helpers --------------------------------------------------------------

    fn show_error(&mut self, resp: &serde_json::Value) {
        let msg = resp
            .get("message")
            .or_else(|| resp.get("reason"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        self.last_error = msg.to_string();
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn str_field(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string()
}

/// Tolerant boolean parsing. The server may return the string "true"/"false"
/// (any casing), a real boolean, or the number 1/0. Anything truthy in that
/// sense reads as `true`; `null`/missing reads as `false`.
fn bool_field(v: Option<&serde_json::Value>) -> bool {
    match v {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::String(s)) => {
            let s = s.trim();
            s.eq_ignore_ascii_case("true") || s == "1"
        }
        Some(serde_json::Value::Number(n)) => n.as_i64() == Some(1) || n.as_f64() == Some(1.0),
        _ => false,
    }
}

/// Compute the remaining time string from an expiration timestamp.
fn remaining_time(expiry: &str) -> String {
    // Lifetime licenses are returned by the server as the literal "Never".
    if expiry.trim().eq_ignore_ascii_case("never") {
        return "Lifetime".to_string();
    }
    let ts = match parse_timestamp(expiry) {
        Some(t) => t,
        None => return "0 Years : 0 Months : 0 Days : 0 Hours : 0 Mins".to_string(),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let secs = (ts - now).max(0);

    let mins = secs / 60;
    let hours = mins / 60;
    let mins = mins % 60;
    let days = hours / 24;
    let hours = hours % 24;
    let months = days / 30;
    let days = days % 30;
    let years = months / 12;
    let months = months % 12;

    format!(
        "{} Years : {} Months : {} Days : {} Hours : {} Mins",
        years, months, days, hours, mins
    )
}

/// Best-effort parse of a server timestamp. Accepts:
///   * ISO-8601 timestamps: `2026-08-26T12:00:00.000Z`, `+HH:MM`/`-HH:MM` offsets
///   * Unix epoch seconds, or millisecond epoch when the value is 13+ digits
/// Returns Unix seconds, or `None` when the string cannot be interpreted.
pub fn parse_timestamp(s: &str) -> Option<i64> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    // Numeric epoch (seconds or milliseconds)?
    if let Ok(n) = t.parse::<i64>() {
        return Some(if t.len() >= 13 { n / 1000 } else { n });
    }
    if let Ok(f) = t.parse::<f64>() {
        let n = f as i64;
        return Some(if t.len() >= 13 { n / 1000 } else { n });
    }
    parse_iso_secs(t)
}

/// Parse an ISO-8601 date-time into Unix seconds.
/// Accepted shapes: `YYYY-MM-DDTHH:MM:SS`, `YYYY-MM-DDTHH:MM:SS.sss`,
/// with a trailing `Z` or a `+HH:MM` / `-HH:MM` offset.
fn parse_iso_secs(t: &str) -> Option<i64> {
    let (base, offset_secs) = split_iso_offset(t)?;
    let (date, time) = base.split_once('T')?;
    let mut dit = date.split('-');
    let y: i64 = dit.next()?.parse().ok()?;
    let m: i64 = dit.next()?.parse().ok()?;
    let d: i64 = dit.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let mut tit = time.split(':');
    let hh: i64 = tit.next()?.parse().ok()?;
    let mm: i64 = tit.next()?.parse().ok()?;
    let sec_part = tit.next().unwrap_or("0");
    let ss: i64 = sec_part.split('.').next()?.parse().ok()?;
    if hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    let days = days_from_civil(y, m, d);
    Some(days * 86_400 + hh * 3_600 + mm * 60 + ss - offset_secs)
}

/// Split an ISO-8601 timezone suffix off a timestamp.
/// Returns `(datetime, offset_seconds)`; naive timestamps are treated as UTC.
fn split_iso_offset(t: &str) -> Option<(&str, i64)> {
    let t = t.trim();
    if let Some(rest) = t.strip_suffix('Z') {
        return Some((rest, 0));
    }
    if let Some(rest) = t.strip_suffix('z') {
        return Some((rest, 0));
    }
    for (i, c) in t.bytes().enumerate().rev() {
        if c == b'+' || c == b'-' {
            let (base, off) = t.split_at(i);
            let sign = if c == b'-' { -1i64 } else { 1i64 };
            let digits = off[1..].trim_start_matches(':');
            let mut pit = digits.split(':');
            let hh: i64 = pit.next()?.parse().ok()?;
            let mm: i64 = pit.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            if hh > 23 || mm > 59 {
                return None;
            }
            return Some((base, sign * (hh * 3_600 + mm * 60)));
        }
    }
    Some((t, 0))
}

/// Convert a proleptic Gregorian calendar date to a day count (Howard
/// Hinnant's civil-from-days inverse). Valid for the range used by timestamps.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Path to `login.json` next to the current executable.
fn login_json_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("login.json")))
        .unwrap_or_else(|| PathBuf::from("login.json"))
}

/// Open a URL in the default browser / handler using platform commands.
fn open_in_browser(url: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn()
            .map(|_| true)
            .unwrap_or(false)
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(url)
            .spawn()
            .map(|_| true)
            .unwrap_or(false)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open")
            .arg(url)
            .spawn()
            .map(|_| true)
            .unwrap_or(false)
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_family = "unix")))]
    {
        let _ = url;
        false
    }
}

// ---------------------------------------------------------------------------
// HWID
// ---------------------------------------------------------------------------

/// Stable machine fingerprint: DJB2 hashes of system identifiers, hex
/// encoded. Returns `"UNKNOWN_HWID"` when nothing usable could be gathered.
pub fn get_hwid() -> String {
    let mut seed: Option<String> = None;

    #[cfg(target_os = "windows")]
    {
        // Prefer WMI machine UUID via PowerShell.
        if let Some(id) = wmi_machine_id() {
            if !id.is_empty() {
                seed = Some(id);
            }
        }
    }

    // Env-based identifiers available on most platforms.
    if seed.is_none() {
        for var in ["COMPUTERNAME", "HOSTNAME", "USERNAME", "USER"] {
            if let Ok(v) = std::env::var(var) {
                if !v.is_empty() {
                    seed = Some(v);
                    break;
                }
            }
        }
    }

    // Hostname via `hostname` command as a final fallback.
    if seed.is_none() {
        if let Ok(out) = std::process::Command::new("hostname").output() {
            let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !name.is_empty() {
                seed = Some(name);
            }
        }
    }

    match seed {
        Some(s) => format!("{:08x}{:08x}", djb2_hash(&s), djb2_xor(&s)),
        None => "UNKNOWN_HWID".to_string(),
    }
}

/// DJB2 hash with seed 5381.
pub fn djb2_hash(input: &str) -> u32 {
    let mut hash: u32 = 5381;
    for b in input.as_bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(*b as u32);
    }
    hash
}

/// Second DJB2-style hash (XOR variant) with seed 0xDEADBEEF.
pub fn djb2_xor(input: &str) -> u32 {
    let mut hash: u32 = 0xDEAD_BEEF;
    for b in input.as_bytes() {
        hash = hash.wrapping_mul(33) ^ (*b as u32);
    }
    hash
}

/// Fetch the Windows machine UUID via WMI (PowerShell one-liner).
#[cfg(target_os = "windows")]
fn wmi_machine_id() -> Option<String> {
    let script = "(Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID";
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn djb2_is_deterministic() {
        assert_eq!(djb2_hash("hello"), djb2_hash("hello"));
        assert_eq!(djb2_xor("world"), djb2_xor("world"));
    }

    #[test]
    fn hwid_nonempty() {
        let h = get_hwid();
        assert!(!h.is_empty());
    }

    #[test]
    fn remaining_time_format() {
        assert!(remaining_time("").contains("Years"));
        assert!(remaining_time("").contains("Mins"));
    }

    #[test]
    fn channel_parse_with_extra_fields() {
        let json =
            r#"{"id":"c1","name":"general","cooldown_unit":"sec","cooldown_time":5,"icon":"star"}"#;
        let ch: Channel = serde_json::from_str(json).unwrap();
        assert_eq!(ch.id, "c1");
        assert_eq!(ch.name, "general");
        assert_eq!(ch.cooldown_time, 5);
        assert_eq!(ch.extra.get("icon").unwrap().as_str(), Some("star"));
    }

    #[test]
    fn parse_sec_timestamp() {
        assert_eq!(parse_timestamp("2500000000"), Some(2500000000));
    }

    #[test]
    fn parse_ms_timestamp() {
        assert_eq!(parse_timestamp("2500000000000"), Some(2500000000));
    }
}

#[cfg(test)]
mod parsing_tests {
    use super::*;

    #[test]
    fn chat_identity_fields_decode() {
        let message: Message = serde_json::from_str(r#"{"id":"m1","channelId":"general","senderId":"u1","sender":"أهلا","avatarId":"avatar-2","content":"**hi**","timeSent":"2026-01-01T00:00:00Z"}"#).unwrap();
        assert_eq!(message.channel_id, "general");
        assert_eq!(message.sender_id, "u1");
        assert_eq!(message.avatar_id, "avatar-2");
        assert_eq!(message.sender, "أهلا");
        let profile: ChatProfile =
            serde_json::from_str(r#"{"profileId":"u1","nickname":"أهلا","avatarId":"avatar-2"}"#)
                .unwrap();
        assert_eq!(profile.id, message.sender_id);
    }

    #[test]
    fn iso_utc_parse() {
        // 2026-08-26T12:00:00Z
        let got = parse_timestamp("2026-08-26T12:00:00.000Z").unwrap();
        assert!(got > 1_700_000_000);
    }

    #[test]
    fn iso_offset_parse() {
        // 2026-08-26T12:00:00+02:00 == 10:00:00Z
        let with_offset = parse_timestamp("2026-08-26T12:00:00+02:00").unwrap();
        let utc = parse_timestamp("2026-08-26T10:00:00Z").unwrap();
        assert_eq!(with_offset, utc);
    }

    #[test]
    fn bool_field_tolerates_strings() {
        assert!(bool_field(Some(&serde_json::json!("true"))));
        assert!(bool_field(Some(&serde_json::json!("TRUE"))));
        assert!(bool_field(Some(&serde_json::json!("1"))));
        assert!(bool_field(Some(&serde_json::json!(1))));
        assert!(bool_field(Some(&serde_json::json!(true))));
        assert!(!bool_field(Some(&serde_json::json!("false"))));
        assert!(!bool_field(Some(&serde_json::json!(0))));
        assert!(!bool_field(Some(&serde_json::json!(false))));
        assert!(!bool_field(Some(&serde_json::Value::Null)));
        assert!(!bool_field(None));
    }

    #[test]
    fn never_expiry_is_none() {
        assert!(parse_timestamp("Never").is_none());
    }
}
