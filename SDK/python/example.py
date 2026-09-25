"""
Authenticity Python SDK - Example Usage
=======================================

A self-contained example that demonstrates every feature of the Python SDK.
Replace the placeholder credentials below with your real values and run it.

    python example.py
"""

import os
import time

from Authenticity import Authenticity, SavedCredentials

# --------------------------------------------------------------------------- #
# 1. Replace these with your actual values from the dashboard.
# --------------------------------------------------------------------------- #
OWNER_ID = ""            # <- your owner ID
APP_ID = ""              # <- your application ID
API_URL = ""             # <- set AUTH_API_URL to your /api/v1/client URL
VERSION = "1.0.0"
LICENSE_KEY = ""         # optional for license-key login

# How often to ping the server to keep the session alive (seconds).
CHECK_SESSION_INTERVAL = 15


def clear_screen() -> None:
    import os

    os.system("cls" if os.name == "nt" else "clear")


def authenticate(client: Authenticity) -> bool:
    """Try auto-login from saved credentials, else manual login."""
    saved: SavedCredentials = Authenticity.load_credentials()
    if saved["is_valid"]:
        print("--- Authenticity Auto-Login ---")
        if saved["login_type"] == 1:
            client.set_license_key(saved["license_key"])
            print("Logging in with saved license key...")
            if client.login():
                print("Auto-login successful!")
                return True
        elif saved["login_type"] == 2:
            if client.login_with_credentials(saved["username"], saved["password"]):
                print("Auto-login successful!")
                return True
        print("Auto-login failed, falling back to manual login...")

    print("--- Authenticity Login ---")
    choice = input("License key (1) or Username/Password (2)? ").strip()
    if choice == "1":
        key = input("License key: ").strip()
        client.set_license_key(key)
        Authenticity.save_credentials(1, license_key=key)
        return client.login()
    else:
        user = input("Username: ").strip()
        pwd = input("Password: ").strip()
        Authenticity.save_credentials(2, username=user, password=pwd)
        return client.login_with_credentials(user, pwd)


def heartbeat(client: Authenticity) -> bool:
    """Keep the session valid; returns False when the session is rejected."""
    if not client.check_session():
        print("Session invalid:", client.get_last_error())
        return False
    print("Session is valid.")
    return True


def main() -> None:
    client = Authenticity(OWNER_ID, APP_ID, API_URL, VERSION, LICENSE_KEY)

    # Check for a required update before sending login credentials.
    update = client.check_for_update()
    if update and update.get("update_required"):
        print("Update required:", update.get("current_version", ""))
        if update.get("update_link"):
            print("Download:", update["update_link"])
        return

    if not authenticate(client):
        print("Authentication failed:", client.get_last_error())
        return

    session = client.get_session()
    app = client.get_app_data()
    print("\nWelcome,", session["username"])
    print("Application:", app["name"], app["version"], "-", app["status"])
    print("Expiry:", session["expiry"])
    print("Time remaining:", client.get_remaining_time())

    # 2. Demonstrate the core SDK features.
    print("\n--- Feature Demo ---")

    # Remote variable
    var_value = client.get_variable("welcomeMessage")
    if var_value:
        print("welcomeMessage:", var_value)

    # Send a log entry
    client.log("Application started successfully", "info")

    # Chat
    channels = client.get_channels()
    print(f"Chat channels: {len(channels)}")
    for channel in channels:
        print(" -", channel.get("name", channel.get("id", "?")))
        if channel.get("id"):
            messages = client.get_messages(channel["id"])
            print(f"   {len(messages)} recent message(s)")
            if messages:
                last = messages[-1]
                print("   Last:", last.get("sender"), "->", last.get("content"))

    # Sending is opt-in so the example never publishes a comment by accident.
    profile = client.get_chat_profile()
    if profile:
        print("Chat profile:", profile["nickname"], profile["avatarId"])
    if os.getenv("AUTH_SEND_COMMENT") == "true" and channels:
        channel_id = channels[0].get("id")
        if channel_id and client.send_message(channel_id, "Hello from the Python SDK example!"):
            print("Comment sent.")
        else:
            print("Comment failed:", client.get_last_error())

    # Trigger a webhook
    client.trigger_webhook("onStart", "user logged in")

    # File download check (opt-in). Set AUTH_FILE_ID to a file ID from
    # dashboard/files, then verify the bytes land on disk and the dashboard
    # Downloads counter increments after refresh.
    file_id = os.getenv("AUTH_FILE_ID", "")
    if file_id:
        data = client.download_file(file_id)
        if data:
            out = "downloaded_{}.bin".format(file_id)
            with open(out, "wb") as fh:
                fh.write(data)
            print("Downloaded {} bytes -> {} (verified)".format(len(data), out))
        else:
            print("Download failed:", client.get_last_error())
    else:
        print("Skip file download check (set AUTH_FILE_ID to test it)")

    # 3. Heartbeat loop so the session stays alive.
    print(f"\nHeartbeat every {CHECK_SESSION_INTERVAL}s. Press Ctrl+C to stop.")
    try:
        while heartbeat(client):
            time.sleep(CHECK_SESSION_INTERVAL)
    except KeyboardInterrupt:
        print("\nGoodbye!")


if __name__ == "__main__":
    main()
