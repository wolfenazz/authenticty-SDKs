package authenticity

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// credentialsFileName returns the absolute path to login.json, which is stored
// next to the current executable.
func credentialsFileName() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(exe)
	return filepath.Join(dir, loginJSONFile), nil
}

// SaveCredentials persists the auto-login information to login.json next to the
// executable. It returns true on success and records any error on the client.
//
// Validation follows the shared SDK contract:
//   - LoginType 1 (license) is valid when LicenseKey is non-empty.
//   - LoginType 2 (username/password) is valid when both Username and Password
//     are non-empty.
//
// The unvalidated credentials are still written so that the raw values are
// preserved; the IsValid flag reflects the validation outcome.
func (c *Client) SaveCredentials(loginType int, licenseKey, username, password string) bool {
	creds := SavedCredentials{
		LoginType:  loginType,
		LicenseKey: licenseKey,
		Username:   username,
		Password:   password,
		IsValid:    credentialsValid(loginType, licenseKey, username, password),
	}

	path, err := credentialsFileName()
	if err != nil {
		c.setErr("authenticity: cannot locate executable directory: " + err.Error())
		return false
	}

	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		c.setErr("authenticity: failed to encode credentials: " + err.Error())
		return false
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		c.setErr("authenticity: failed to write credentials: " + err.Error())
		return false
	}
	c.setErr("")
	return true
}

// LoadCredentials reads the auto-login file next to the executable. If the file
// is missing or unreadable the returned credentials have IsValid = false.
func (c *Client) LoadCredentials() SavedCredentials {
	path, err := credentialsFileName()
	if err != nil {
		c.setErr("authenticity: cannot locate executable directory: " + err.Error())
		return SavedCredentials{IsValid: false}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			c.setErr("authenticity: failed to read credentials: " + err.Error())
		}
		return SavedCredentials{IsValid: false}
	}

	var creds SavedCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		c.setErr("authenticity: failed to parse credentials: " + err.Error())
		return SavedCredentials{IsValid: false}
	}

	creds.IsValid = credentialsValid(creds.LoginType, creds.LicenseKey, creds.Username, creds.Password)
	c.setErr("")
	return creds
}

// DeleteCredentials removes the auto-login file next to the executable. It
// returns true when the file was removed (or did not exist).
func (c *Client) DeleteCredentials() bool {
	path, err := credentialsFileName()
	if err != nil {
		c.setErr("authenticity: cannot locate executable directory: " + err.Error())
		return false
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.setErr("")
			return true
		}
		c.setErr("authenticity: failed to delete credentials: " + err.Error())
		return false
	}
	c.setErr("")
	return true
}

// credentialsValid implements the shared auto-login validation rules.
func credentialsValid(loginType int, licenseKey, username, password string) bool {
	switch loginType {
	case LoginTypeLicense:
		return licenseKey != ""
	case LoginTypeCredentials:
		return username != "" && password != ""
	default:
		return false
	}
}
