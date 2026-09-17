package authenticity

import (
	"fmt"
	"strings"
	"time"
)

// SetLicenseKey updates the client's license key.
func (c *Client) SetLicenseKey(key string) {
	c.LicenseKey = key
}

// GetSession returns a copy of the current session state.
func (c *Client) GetSession() Session {
	return c.Session
}

// GetAppData returns a copy of the current application metadata.
func (c *Client) GetAppData() AppData {
	return c.AppData
}

// GetLastError returns the most recent error message, or an empty string if
// there is none.
func (c *Client) GetLastError() string {
	return c.LastError
}

// GetUpdateLink returns the update link from the session. Login responses do
// not include an update link, so this typically returns an empty string; the
// field is retained for parity with the other SDKs.
func (c *Client) GetUpdateLink() string {
	return c.Session.UpdateLink
}

// GetHwid returns the generated hardware ID of this machine.
func (c *Client) GetHwid() string {
	return c.Hwid
}

// GetHash returns the secondary machine fingerprint hash.
func (c *Client) GetHash() string {
	return c.Hash
}

// GetRemainingTime computes a human-readable remaining-time string from the
// session expiry token in the format used by the other SDKs:
//
//	"X Years : X Months : X Days : X Hours : X Mins"
//
// The server expiry string is parsed leniently: if it cannot be interpreted,
// an all-zero breakdown is returned.
func (c *Client) GetRemainingTime() string {
	years, months, days, hours, mins := c.remainingBreakdown()
	return fmt.Sprintf("%d Years : %d Months : %d Days : %d Hours : %d Mins",
		years, months, days, hours, mins)
}

// remainingBreakdown decomposes the session expiry into calendar parts. It is a
// best-effort parse of the server-provided expiry string.
func (c *Client) remainingBreakdown() (years, months, days, hours, mins int) {
	exp := strings.TrimSpace(c.Session.Expiry)
	if exp == "" {
		return 0, 0, 0, 0, 0
	}
	// Lifetime licenses are returned by the server as the literal "Never".
	// Treat them as a far-future expiry so callers see a sensible breakdown.
	if strings.EqualFold(exp, "Never") {
		exp = "2099-12-31T00:00:00Z"
	}

	// Try a few common layouts.
	layouts := []string{
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02",
		"01/02/2006 15:04:05",
		"2006/01/02 15:04:05",
	}
	var t time.Time
	for _, l := range layouts {
		if parsed, err := time.Parse(l, exp); err == nil {
			t = parsed
			break
		}
	}
	if t.IsZero() {
		// Also try parsing a raw millisecond timestamp.
		var ms int64
		if _, err := fmt.Sscanf(exp, "%d", &ms); err == nil && ms > 0 {
			t = time.UnixMilli(ms)
		}
	}
	if t.IsZero() {
		return 0, 0, 0, 0, 0
	}

	now := time.Now()
	if t.Before(now) {
		return 0, 0, 0, 0, 0
	}

	d := t.Sub(now)
	years = int(d / (365 * 24 * time.Hour))
	d -= time.Duration(years) * 365 * 24 * time.Hour
	months = int(d / (30 * 24 * time.Hour))
	d -= time.Duration(months) * 30 * 24 * time.Hour
	days = int(d / (24 * time.Hour))
	d -= time.Duration(days) * 24 * time.Hour
	hours = int(d / time.Hour)
	d -= time.Duration(hours) * time.Hour
	mins = int(d / time.Minute)
	return
}
