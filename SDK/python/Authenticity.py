"""
Authenticity Python SDK
========================

A complete, dependency-free (standard library only) Python client for the
Authenticity authentication system. It mirrors every endpoint exposed by the
`/api/v1/client/*` routes of the dashboard backend, matching the behaviour of
the official C++ and C# SDKs.

Endpoints implemented
---------------------
    POST  /auth/login               License-key login
    POST  /auth/login-user          Username/password login
    POST  /auth/register            Register a new user with a license key
    POST  /auth/check               Heartbeat / session validation
    POST  /auth/check-blacklist     IP / HWID / user blacklist check
    POST  /auth/ban                 Self-ban (anti-tampering)
    POST  /vars/get                 Fetch a remote variable
    POST  /files/download           Resolve / download a file
    POST  /webhooks/trigger         Trigger a remote webhook
    POST  /logs/add                 Send an application log
    POST  /chat/channels            List chat channels
    POST  /chat/messages            Fetch chat messages
    PUT   /chat/messages            Send a chat message
    POST  /app/update               Pre-login version/update check

Usage is identical across all supported languages:

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
    else:
        print("Login failed:", client.get_last_error())
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

__all__ = ["Authenticity", "Session", "AppData", "SavedCredentials"]

# --------------------------------------------------------------------------- #
# Data structures
# --------------------------------------------------------------------------- #


class Session(Dict[str, Any]):
    """User session information returned by a successful login."""

    def __init__(self) -> None:
        super().__init__(
            token="",
            expiry="",
            username="",
            ip="",
            hwid="",
            level=0,
            is_valid=False,
            update_link="",
        )


class AppData(Dict[str, Any]):
    """Application metadata returned alongside the session."""

    def __init__(self) -> None:
        super().__init__(
            name="",
            version="",
            status="",
            hwid_lock=False,
        )


class SavedCredentials(Dict[str, Any]):
    """
    Saved auto-login credentials.

    login_type: 1 = license key, 2 = username/password
    """

    def __init__(self) -> None:
        super().__init__(
            login_type=0,
            license_key="",
            username="",
            password="",
            is_valid=False,
        )


# --------------------------------------------------------------------------- #
# Hardware-ID helper (mirrors the C#/C++ DJB2-based implementation)
# --------------------------------------------------------------------------- #


def _djb2_hash(data: str) -> int:
    """DJB2-style hash used to keep the generated HWID stable and short."""
    hash_val = 5381
    for ch in data:
        hash_val = (((hash_val << 5) + hash_val) + ord(ch)) & 0xFFFFFFFFFFFFFFFF
    return hash_val


def _djb2_hash2(data: str) -> int:
    """Second DJB2 variant (XOR-based) for extra entropy (matches C# SDK)."""
    hash_val = 0xDEADBEEF
    for ch in data:
        hash_val = (((hash_val << 5) + hash_val) ^ ord(ch)) & 0xFFFFFFFFFFFFFFFF
    return hash_val


def _machine_fingerprint() -> str:
    """
    Gather stable machine identifiers.

    On Windows this tries WMI (CPU ID, volume serial, BIOS). On other
    platforms it falls back to a hash of stable machine metadata. Returns
    the raw concatenated string; callers hash it with `generate_hwid`.
    """
    raw = ""
    system = platform.system()

    if system == "Windows":
        raw += _wmi_query("SELECT ProcessorId FROM Win32_Processor", "ProcessorId")
        raw += _wmi_query(
            "SELECT VolumeSerialNumber FROM Win32_LogicalDisk WHERE DeviceID = 'C:'",
            "VolumeSerialNumber",
        )
        raw += platform.node()
        raw += _wmi_query("SELECT SerialNumber FROM Win32_BIOS", "SerialNumber")
    else:
        raw += platform.node()
        raw += platform.machine()
        raw += socket.gethostname()

    return raw


def _wmi_query(query: str, field: str) -> str:
    """Run a WMI query via PowerShell (Windows only). Best-effort, empty on error."""
    if platform.system() != "Windows":
        return ""
    try:
        cmd = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$r = Get-WmiObject -Query '" + query + "'; $r." + field,
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=0x08000000,  # CREATE_NO_WINDOW
        )
        return (result.stdout or "").strip()
    except Exception:
        return ""


def generate_hwid() -> str:
    """Generate a stable, language-consistent hardware ID for this machine."""
    try:
        raw = _machine_fingerprint()
        if not raw:
            raw = socket.gethostname() + platform.node() + platform.machine()
        h1 = _djb2_hash(raw)
        h2 = _djb2_hash2(raw)
        return "{:X}{:X}".format(h1, h2)
    except Exception:
        return "UNKNOWN_HWID"

# --------------------------------------------------------------------------- #
# Main client
# --------------------------------------------------------------------------- #


class Authenticity:
    """
    Authenticity client.

    :param owner_id:   Your owner ID from the dashboard.
    :param app_id:     Your application ID from the dashboard.
    :param api_url:    Full API base URL, e.g. ``https://.../api/v1/client``.
    :param version:    Your application version string.
    :param license_key: Optional default license key for license login.
    """

    def __init__(
        self,
        owner_id: str,
        app_id: str,
        api_url: str,
        version: str,
        license_key: str = "",
    ) -> None:
        self._owner_id = owner_id
        self._app_id = app_id
        self._api_url = api_url.rstrip("/")
        self._version = version
        self._license_key = license_key

        self._session = Session()
        self._app_data = AppData()
        self._hwid = generate_hwid()
        self._hash = _hash_executable()
        self._last_error = ""

    # ------------------------------------------------------------------ #
    # Authentication
    # ------------------------------------------------------------------ #

    def login(self) -> bool:
        """Authenticate using the license key. Returns True on success."""
        body = {
            "ownerId": self._owner_id,
            "appId": self._app_id,
            "licenseKey": self._license_key,
            "hwid": self._hwid,
            "version": self._version,
            "hash": self._hash,
        }
        response = self._request("/auth/login", "POST", body)

        if self._parse_response(response):
            return True

        if self._json_value(response, "message") == "Your IP address has been blacklisted":
            self._last_error = "Your IP address has been blacklisted"
            return False

        self._last_error = self._json_value(response, "message")
        return False

    def login_with_credentials(self, username: str, password: str) -> bool:
        """Authenticate using a username and password."""
        body = {
            "ownerId": self._owner_id,
            "appId": self._app_id,
            "username": username,
            "password": password,
            "hwid": self._hwid,
            "version": self._version,
            "hash": self._hash,
        }
        response = self._request("/auth/login-user", "POST", body)

        if self._parse_response(response):
            return True

        if self._json_value(response, "message") == "Your IP address has been blacklisted":
            self._last_error = "Your IP address has been blacklisted"
            return False

        self._last_error = self._json_value(response, "message")
        return False

    def check_for_update(self) -> Optional[Dict[str, Any]]:
        """Check the server version before login; returns None on failure."""
        response = self._request(
            "/app/update",
            "POST",
            {"ownerId": self._owner_id, "appId": self._app_id, "version": self._version},
            authorized=False,
        )
        if self._json_value(response, "success") != "true":
            self._last_error = self._json_value(response, "message") or "Update check failed"
            return None
        return {
            "update_required": self._json_value(response, "updateRequired") == "true",
            "client_version": self._json_value(response, "clientVersion") or self._version,
            "current_version": self._json_value(response, "currentVersion"),
            "update_link": self._json_value(response, "updateLink"),
            "app_name": self._json_value(response, "appName"),
            "app_status": self._json_value(response, "appStatus"),
        }

    def register(
        self, username: str, password: str, license_key: Optional[str] = None
    ) -> bool:
        """Register a new user with a license key."""
        body = {
            "ownerId": self._owner_id,
            "appId": self._app_id,
            "username": username,
            "password": password,
            "licenseKey": license_key if license_key is not None else self._license_key,
            "hwid": self._hwid,
            "version": self._version,
            "hash": self._hash,
        }
        response = self._request("/auth/register", "POST", body)

        if self._json_value(response, "success") == "true":
            return True

        self._last_error = self._json_value(response, "message")
        return False

    def check_session(self) -> bool:
        """Validate the current session (heartbeat). Returns True while valid."""
        if not self._session["is_valid"]:
            return False

        body = {"token": self._session["token"], "appId": self._app_id, "hwid": self._hwid}
        response = self._request("/auth/check", "POST", body)

        if self._json_value(response, "success") == "true":
            return True

        is_expired = self._json_value(response, "expired") == "true"
        reason = self._json_value(response, "reason") or self._json_value(response, "message")

        if is_expired:
            self._session["is_valid"] = False
            if reason == "License expired":
                self._last_error = (
                    "Your license has expired. The application will now close."
                )
            elif reason == "Session expired":
                self._last_error = "Your session has expired. Please log in again."
            else:
                self._last_error = reason or "Session is no longer valid"
        else:
            self._session["is_valid"] = False
            self._last_error = self._json_value(response, "message") or (
                "Session is no longer valid"
            )

        return False

    def check_blacklist(self) -> bool:
        """
        Check whether this client (IP / HWID) is blacklisted.

        Returns True if blacklisted (caller should normally refuse to run).
        """
        body = {
            "ownerId": self._owner_id,
            "appId": self._app_id,
            "hwid": self._hwid,
        }
        response = self._request("/auth/check-blacklist", "POST", body)
        message = self._json_value(response, "message")

        if self._is_blacklisted(response, message):
            self._last_error = message or "Your IP address has been blacklisted"
            return True
        return False

    def ban(self, reason: str) -> bool:
        """Self-ban the current session (usually called on tamper detection)."""
        if not self._session["is_valid"]:
            return False

        body = {
            "token": self._session["token"],
            "appId": self._app_id,
            "reason": reason,
        }
        response = self._request("/auth/ban", "POST", body)
        self._session["is_valid"] = False
        return self._json_value(response, "success") == "true"


    # ------------------------------------------------------------------ #
    # Remote configuration / files / webhooks / logs
    # ------------------------------------------------------------------ #

    def get_variable(self, name: str) -> str:
        """Fetch a remote variable value by name (empty string if not found)."""
        if not self._session["is_valid"]:
            return ""

        body = {
            "token": self._session["token"],
            "appId": self._app_id,
            "name": name,
        }
        response = self._request("/vars/get", "POST", body)
        return self._json_value(response, "value")

    def download_file(self, file_id: str) -> bytes:
        """
        Download a file by ID or name.

        Resolves the file through the API, then downloads its raw bytes.
        Returns ``b""`` on failure (check :meth:`get_last_error`).
        """
        if not self._session["is_valid"]:
            self._last_error = "Session is invalid"
            return b""

        body = {
            "token": self._session["token"],
            "appId": self._app_id,
            "fileId": file_id,
        }
        response = self._request("/files/download", "POST", body)
        message = self._json_value(response, "message")

        if self._is_blacklisted(response, message):
            self._session["is_valid"] = False
            self._last_error = message or "Your IP address has been blacklisted"
            return b""

        if self._json_value(response, "success") != "true":
            self._last_error = message or "Download failed"
            return b""

        url = self._json_value(response, "url") or self._json_value(response, "downloadUrl")
        if not url:
            self._last_error = "Download URL not found in response"
            return b""

        try:
            return self._download_bytes(url)
        except Exception as exc:
            self._last_error = "Failed to download file: {}".format(exc)
            return b""

    def download_file_direct(self, file_id: str) -> bool:
        """
        Resolve a file and open its URL in the user's default browser.

        Returns True if the file was resolved successfully.
        """
        if not self._session["is_valid"]:
            self._last_error = "Session is invalid"
            return False

        body = {
            "token": self._session["token"],
            "appId": self._app_id,
            "fileId": file_id,
        }
        response = self._request("/files/download", "POST", body)
        message = self._json_value(response, "message")

        if self._is_blacklisted(response, message):
            self._session["is_valid"] = False
            self._last_error = message or "Your IP address has been blacklisted"
            return False

        if self._json_value(response, "success") == "true":
            url = self._json_value(response, "url") or self._json_value(response, "downloadUrl")
            if url:
                _open_url(url)
                return True
            self._last_error = "Download URL not found in response"
            return False

        self._last_error = message or "Unknown error"
        return False

    def trigger_webhook(self, webhook_name: str, data: str = "") -> bool:
        """Trigger a named webhook with optional custom data."""
        if not self._session["is_valid"]:
            self._last_error = "Session is invalid"
            return False

        body = {
            "token": self._session["token"],
            "appId": self._app_id,
            "webhookName": webhook_name,
            "data": data,
        }
        response = self._request("/webhooks/trigger", "POST", body)
        return self._json_value(response, "success") == "true"

    def log(self, data: str, log_type: str = "info") -> None:
        """Send an application log entry to the dashboard."""
        if not self._session["is_valid"]:
            return

        body = {
            "token": self._session["token"],
            "appId": self._app_id,
            "data": data,
            "type": log_type,
        }
        self._request("/logs/add", "POST", body)


    # ------------------------------------------------------------------ #
    # Chat
    # ------------------------------------------------------------------ #

    def get_channels(self) -> List[Dict[str, Any]]:
        """Fetch the list of chat channels for this application."""
        if not self._session["is_valid"]:
            self._last_error = "Session is invalid"
            return []

        body = {"token": self._session["token"], "appId": self._app_id}
        response = self._request("/chat/channels", "POST", body)
        message = self._json_value(response, "message")

        if self._is_blacklisted(response, message):
            self._session["is_valid"] = False
            self._last_error = message or "Your IP address has been blacklisted"
            return []

        if self._json_value(response, "success") == "true":
            return self._json_array(response, "channels")

        self._last_error = message or "Unknown error"
        return []

    def get_messages(self, channel_id: str) -> List[Dict[str, Any]]:
        """Fetch messages from a specific channel (or ``"all"`` for every channel)."""
        if not self._session["is_valid"]:
            self._last_error = "Session is invalid"
            return []

        body = {
            "token": self._session["token"],
            "appId": self._app_id,
            "channelId": channel_id,
        }
        response = self._request("/chat/messages", "POST", body)
        message = self._json_value(response, "message")

        if self._is_blacklisted(response, message):
            self._session["is_valid"] = False
            self._last_error = message or "Your IP address has been blacklisted"
            return []

        if self._json_value(response, "success") == "true":
            return self._json_array(response, "messages")

        self._last_error = message or "Unknown error"
        return []

    def get_chat_profile(self) -> Optional[Dict[str, str]]:
        """Return the current user's chat identity, or None on failure."""
        if not self._session["is_valid"]:
            self._last_error = "Session is invalid"
            return None
        response = self._request("/chat/profile", "POST", {
            "token": self._session["token"], "appId": self._app_id,
        })
        message = self._json_value(response, "message")
        if self._is_blacklisted(response, message):
            self._session["is_valid"] = False
            self._last_error = message or "Your IP address has been blacklisted"
            return None
        if self._json_value(response, "success") != "true":
            self._last_error = message or "Failed to fetch chat profile"
            return None
        self._last_error = ""
        return {"id": self._json_value(response, "profileId"),
                "nickname": self._json_value(response, "nickname"),
                "avatarId": self._json_value(response, "avatarId")}

    def update_chat_profile(self, nickname: str, avatar_id: str) -> Optional[Dict[str, str]]:
        """Update the chat nickname and application avatar ID."""
        if not self._session["is_valid"]:
            self._last_error = "Session is invalid"
            return None
        response = self._request("/chat/profile", "PUT", {
            "token": self._session["token"], "appId": self._app_id,
            "nickname": nickname, "avatarId": avatar_id,
        })
        message = self._json_value(response, "message")
        if self._is_blacklisted(response, message):
            self._session["is_valid"] = False
            self._last_error = message or "Your IP address has been blacklisted"
            return None
        if self._json_value(response, "success") != "true":
            self._last_error = message or "Failed to update chat profile"
            return None
        self._last_error = ""
        return {"id": self._json_value(response, "profileId"),
                "nickname": self._json_value(response, "nickname"),
                "avatarId": self._json_value(response, "avatarId")}

    def send_message(self, channel_id: str, content: str) -> bool:
        """Send a message to a channel. Returns True on success."""
        if not self._session["is_valid"]:
            self._last_error = "Session is invalid"
            return False

        body = {
            "token": self._session["token"],
            "appId": self._app_id,
            "channelId": channel_id,
            "content": content,
        }
        response = self._request("/chat/messages", "PUT", body)
        message = self._json_value(response, "message")

        if self._is_blacklisted(response, message):
            self._session["is_valid"] = False
            self._last_error = message or "Your IP address has been blacklisted"
            return False

        ok = self._json_value(response, "success") == "true"
        self._last_error = message or ("Message sent" if ok else "Unknown error")
        return ok


    # ------------------------------------------------------------------ #
    # Getters / helpers
    # ------------------------------------------------------------------ #

    def set_license_key(self, license_key: str) -> None:
        """Set or update the license key used for :meth:`login`."""
        self._license_key = license_key

    def get_session(self) -> Session:
        """Return the current session information."""
        return self._session

    def get_app_data(self) -> AppData:
        """Return the application metadata from the server."""
        return self._app_data

    def get_last_error(self) -> str:
        """Return the last error message produced by an API call."""
        return self._last_error

    def get_update_link(self) -> str:
        """Return the update link reported by the server (may be empty)."""
        return self._session["update_link"]

    def get_remaining_time(self) -> str:
        """
        Compute the time remaining until license expiry as a human string,
        e.g. ``"0 Years : 0 Months : 0 Days : 12 Hours : 30 Mins"``.
        """
        replay = self._session["expiry"]
        if not self._session["is_valid"] or not replay:
            return "0 Years : 0 Months : 0 Days : 0 Hours : 0 Mins"

        # Lifetime licenses are returned by the server as the literal "Never".
        if str(replay).strip().lower() == "never":
            return "Lifetime"

        try:
            expiry = _parse_iso(replay)
            now = datetime.now(timezone.utc)
            # Normalise to aware datetimes to avoid naive/aware subtraction errors.
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            diff = expiry - now
            if diff.total_seconds() <= 0:
                return "0 Years : 0 Months : 0 Days : 0 Hours : 0 Mins"
            total = int(diff.total_seconds())

            days, rem = divmod(total, 86400)
            hours, rem = divmod(rem, 3600)
            minutes, _ = divmod(rem, 60)

            years, days = divmod(days, 365)
            months, days = divmod(days, 30)

            return "{} Years : {} Months : {} Days : {} Hours : {} Mins".format(
                years, months, days, hours, minutes
            )
        except Exception:
            return "0 Years : 0 Months : 0 Days : 0 Hours : 0 Mins"

    # ------------------------------------------------------------------ #
    # Credential management (login.json auto-login)
    # ------------------------------------------------------------------ #

    @staticmethod
    def _credentials_path() -> str:
        """Path of the login.json file next to the running script."""
        directory = os.path.dirname(os.path.abspath(sys.argv[0] or "."))
        return os.path.join(directory, "login.json")

    @classmethod
    def credentials_path(cls) -> str:
        """Return the path of the auto-login credentials file."""
        return cls._credentials_path()

    @classmethod
    def save_credentials(
        cls,
        login_type: int,
        license_key: str = "",
        username: str = "",
        password: str = "",
    ) -> bool:
        """Save auto-login credentials to login.json."""
        try:
            data = {
                "loginType": login_type,
                "licenseKey": license_key,
                "username": username,
                "password": password,
            }
            with open(cls._credentials_path(), "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=4)
            return True
        except Exception:
            return False

    @classmethod
    def load_credentials(cls) -> SavedCredentials:
        """Load and validate auto-login credentials from login.json."""
        creds = SavedCredentials()
        try:
            with open(cls._credentials_path(), "r", encoding="utf-8") as fh:
                data = json.load(fh)
            creds["login_type"] = int(data.get("loginType", 0))
            creds["license_key"] = data.get("licenseKey", "")
            creds["username"] = data.get("username", "")
            creds["password"] = data.get("password", "")

            if creds["login_type"] == 1 and creds["license_key"]:
                creds["is_valid"] = True
            elif creds["login_type"] == 2 and creds["username"] and creds["password"]:
                creds["is_valid"] = True
        except Exception:
            creds = SavedCredentials()
        return creds

    @classmethod
    def delete_credentials(cls) -> bool:
        """Delete the auto-login credentials file if it exists."""
        try:
            if os.path.exists(cls._credentials_path()):
                os.remove(cls._credentials_path())
                return True
        except Exception:
            pass
        return False


    # ------------------------------------------------------------------ #
    # Internal HTTP / JSON utilities
    # ------------------------------------------------------------------ #

    def _request(
        self,
        endpoint: str,
        method: str,
        body: Dict[str, Any],
        authorized: bool = True,
    ) -> str:
        """
        Perform an HTTP(S) request against the API, returning the raw body
        as a string. Uses only the Python standard library.
        """
        url = self._api_url + endpoint
        payload = json.dumps(body).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Authenticity SDK/1.0 (Python)",
            "Accept": "application/json",
        }
        token = self._session.get("token")
        if authorized and token:
            headers["Authorization"] = "Bearer " + token

        req = urllib.request.Request(url, data=payload, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as err:
            # The API returns error bodies with a non-2xx status; surface the body.
            try:
                return err.read().decode("utf-8", "replace")
            except Exception:
                return json.dumps(
                    {"success": "false", "message": "HTTP {}".format(err.code)}
                )
        except Exception as exc:
            self._last_error = "Network error: {}".format(exc)
            return json.dumps({"success": "false", "message": str(exc)})

    def _download_bytes(self, url: str) -> bytes:
        """Download raw bytes from a URL (excluding API auth headers)."""
        req = urllib.request.Request(
            url, headers={"User-Agent": "Authenticity SDK/1.0 (Python)"}
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read()

    def _parse_response(self, response: str) -> bool:
        """Parse a login response and populate session / app data."""
        self._session["update_link"] = self._json_value(response, "updateLink")
        if self._json_value(response, "success") != "true":
            return False

        token = self._json_value(response, "token")
        if not token:
            self._session["is_valid"] = False
            self._last_error = "authenticity: login response did not include a session token"
            return False

        self._session["is_valid"] = True
        self._session["token"] = token
        self._session["expiry"] = self._json_value(response, "expiry")
        self._session["username"] = self._json_value(response, "username")
        self._session["ip"] = self._json_value(response, "ip")
        self._session["hwid"] = self._hwid
        self._session["update_link"] = self._json_value(response, "updateLink")

        level_str = self._json_value(response, "level")
        try:
            self._session["level"] = int(level_str) if level_str else 0
        except (TypeError, ValueError):
            self._session["level"] = 0

        self._app_data["name"] = self._json_value(response, "appName")
        self._app_data["version"] = self._json_value(response, "appVersion")
        self._app_data["status"] = self._json_value(response, "appStatus")
        self._app_data["hwid_lock"] = self._json_value(response, "hwidLock") == "true"
        return True


    @staticmethod
    def _is_blacklisted(response: str, message: str) -> bool:
        """
        Return True if a response indicates an IP/HWID blacklist event.

        Mirrors the C++/C# SDKs: any failure message that references
        being blacklisted / banned / blocked is treated as a blacklist so the
        client can self-terminate appropriately.
        """
        if message:
            lowered = message.lower()
            if any(
                word in lowered
                for word in ("blacklist", "banned", "blocked", "denied")
            ):
                return True
        return False

    @staticmethod
    def _json_value(json_text: str, key: str) -> str:
        """
        Extract a top-level value by key from a JSON response.

        Tries strict JSON decoding first, then falls back to tolerant string
        parsing so partial or malformed responses behave like the C++/C# SDKs.
        """
        if not json_text:
            return ""
        try:
            data = json.loads(json_text)
            if isinstance(data, dict) and key in data:
                value = data[key]
                if isinstance(value, bool):
                    return "true" if value else "false"
                if value is None:
                    return ""
                return str(value)
        except Exception:
            pass

        # Tolerant regex fallback for malformed / partial responses.
        pattern = '"' + re_key(key) + r'"\s*:\s*'
        match = re_search(pattern, json_text)
        if not match:
            return ""
        rest = json_text[match.end():].lstrip()
        if rest.startswith('"'):
            end = rest.find('"', 1)
            return rest[1:end] if end != -1 else ""
        if rest.startswith("{"):
            depth = 0
            for i, ch in enumerate(rest):
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        return rest[: i + 1]
            return rest
        if rest.startswith("["):
            depth = 0
            for i, ch in enumerate(rest):
                if ch == "[":
                    depth += 1
                elif ch == "]":
                    depth -= 1
                    if depth == 0:
                        return rest[: i + 1]
            return rest
        # Primitive value (number / boolean / null)
        end = 0
        while end < len(rest) and rest[end] not in ",}]":
            end += 1
        return rest[:end].strip()


# --------------------------------------------------------------------------- #

    @staticmethod
    def _json_array(json_text: str, key: str) -> List[Any]:
        """
        Extract an array value by key from a JSON response.

        Returns an empty list when the key is absent, null, or not an array.
        This is used for ``channels`` and ``messages`` collections.
        """
        if not json_text:
            return []
        try:
            data = json.loads(json_text)
            if isinstance(data, dict) and isinstance(data.get(key), list):
                return data[key]
        except Exception:
            pass

        # Tolerant fallback: locate the array and decode it.
        pattern = '"' + re_key(key) + r'"\s*:\s*'
        match = re_search(pattern, json_text)
        if not match:
            return []
        rest = json_text[match.end():].lstrip()
        if not rest.startswith("["):
            return []
        try:
            decoder = json.JSONDecoder()
            arr, _ = decoder.raw_decode(rest)
            return arr if isinstance(arr, list) else []
        except Exception:
            return []

# Module-level helpers
# --------------------------------------------------------------------------- #


def _open_url(url: str) -> bool:
    """Open a URL in the default browser when possible. Best-effort."""
    try:
        system = platform.system()
        if system == "Windows":
            os.startfile(url)  # type: ignore[attr-defined]
        elif system == "Darwin":
            subprocess.Popen(["open", url])
        else:
            subprocess.Popen(["xdg-open", url])
        return True
    except Exception:
        return False


def _hash_executable() -> str:
    """Compute an MD5 hash of the running script/file as an integrity check."""
    try:
        path = os.path.abspath(sys.argv[0] if sys.argv and sys.argv[0] else __file__)
        if os.path.isfile(path):
            with open(path, "rb") as fh:
                return hashlib.md5(fh.read()).hexdigest()
    except Exception:
        pass
    return ""


def _parse_iso(value: str) -> datetime:
    """Parse an ISO-8601 timestamp like ``2025-12-21T14:33:58.000Z``."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        pass

    # Manual fallback: strip fraction / timezone suffix.
    cleaned = value.strip()
    if "." in cleaned:
        cleaned = cleaned.split(".")[0]
    cleaned = cleaned.replace("Z", "").replace("+00:00", "")
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M"):
        try:
            return datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
    raise ValueError("Unparseable ISO timestamp: {!r}".format(value))


def re_key(key: str) -> str:
    """Escape a JSON key for safe use inside a regular expression."""
    import re

    return re.escape(key)


def re_search(pattern: str, text: str):
    """Thin wrapper around ``re.search`` used by :meth:`Authenticity._json_value`."""
    import re

    return re.search(pattern, text)
