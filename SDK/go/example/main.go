// Command example demonstrates the Authenticity Go SDK. It logs in, performs a
// heartbeat, reads a variable, posts a log, triggers a webhook, and reads chat
// channels and messages.
package main

import (
	"fmt"
	"github.com/authenticity/sdk-go/authenticity"
	"os"
)

func main() {
	// Configure the client. APIURL must already end with /api/v1/client.
	ownerID := envOr("AUTH_OWNER_ID", "your-owner-id")
	appID := envOr("AUTH_APP_ID", "your-app-id")
	apiURL := envOr("AUTH_API_URL", "")
	version := envOr("AUTH_VERSION", "1.0.0")

	client := authenticity.NewClient(ownerID, appID, apiURL, version)

	fmt.Println("HWID:", client.GetHwid())

	// Check for a required update before sending login credentials.
	if update := client.CheckForUpdate(); update != nil && update.UpdateRequired {
		fmt.Println("Update required:", update.CurrentVersion)
		if update.UpdateLink != "" {
			fmt.Println("Download:", update.UpdateLink)
		}
		return
	}

	// Try a license-key login if a key was provided.
	if key := os.Getenv("AUTH_LICENSE_KEY"); key != "" {
		client.SetLicenseKey(key)
		fmt.Println("Attempting license login...")
		if !client.Login() {
			fmt.Println("Login failed:", client.GetLastError())
			return
		}
	} else {
		fmt.Println("Attempting username/password login...")
		if !client.LoginWithCredentials(
			envOr("AUTH_USERNAME", "demo"),
			envOr("AUTH_PASSWORD", "demo"),
		) {
			fmt.Println("Login failed:", client.GetLastError())
			return
		}
	}

	fmt.Printf("Logged in as %s (expiry: %s)\n",
		client.GetSession().Username, client.GetSession().Expiry)
	fmt.Println("Remaining:", client.GetRemainingTime())

	// Heartbeat.
	if !client.CheckSession() {
		fmt.Println("Heartbeat failed:", client.GetLastError())
		return
	}
	fmt.Println("Session heartbeat OK")

	// Read a variable.
	val := client.GetVariable("welcomeMessage")
	fmt.Printf("Variable welcomeMessage = %q (err: %s)\n", val, client.GetLastError())

	// Post a log entry.
	client.Log("Initialized Go SDK example", "info")

	// Trigger a webhook.
	if client.TriggerWebhook("onStart", map[string]interface{}{
		"user": client.GetSession().Username,
	}) {
		fmt.Println("Webhook triggered")
	} else {
		fmt.Println("Webhook failed:", client.GetLastError())
	}

	// Chat: list channels and messages.
	if profile, ok := client.GetChatProfile(); ok {
		fmt.Printf("Chat profile: %s (%s)\n", profile.Nickname, profile.AvatarID)
	}
	channels := client.GetChannels()
	fmt.Printf("Channels: %d\n", len(channels))
	for _, ch := range channels {
		fmt.Printf("  - %s (%s)\n", ch.Name, ch.ID)
	}

	messages := client.GetMessages("all")
	fmt.Printf("Messages: %d\n", len(messages))
	for _, m := range messages {
		fmt.Printf("  [%s] %s: %s\n", m.TimeSent, m.Sender, m.Content)
	}

	// Sending is opt-in so the example never publishes a comment by accident.
	if os.Getenv("AUTH_SEND_COMMENT") == "true" && len(channels) > 0 {
		if client.SendMessage(channels[0].ID, "Hello from the Go SDK example!") {
			fmt.Println("Comment sent")
		} else {
			fmt.Println("Comment failed:", client.GetLastError())
		}
	}

	// File download check (opt-in). Set AUTH_FILE_ID to a file ID from
	// dashboard/files, then verify the bytes land on disk and the dashboard
	// Downloads counter increments after refresh.
	if fileID := os.Getenv("AUTH_FILE_ID"); fileID != "" {
		if data, err := client.DownloadFile(fileID); err != nil {
			fmt.Println("Download failed:", err)
		} else if out, werr := os.Create("downloaded_" + fileID + ".bin"); werr != nil {
			fmt.Println("Download save failed:", werr)
		} else {
			n, werr := out.Write(data)
			out.Close()
			if werr != nil || n != len(data) {
				fmt.Println("Download save failed:", client.GetLastError())
			} else {
				fmt.Printf("Downloaded %d bytes -> downloaded_%s.bin (verified)\n", len(data), fileID)
			}
		}
	} else {
		fmt.Println("Skip file download check (set AUTH_FILE_ID to test it)")
	}

	// Save and load auto-login credentials (best-effort).
	client.SaveCredentials(authenticity.LoginTypeLicense, client.LicenseKey, "", "")
	saved := client.LoadCredentials()
	fmt.Printf("Saved credentials valid: %v\n", saved.IsValid)
	client.DeleteCredentials()

	fmt.Println("Example finished successfully")
}

// envOr returns the value of the named environment variable or a fallback.
func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
