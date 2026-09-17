package authenticity

import (
	"net/http"
	"net/url"
	"time"
)

// Client is the main entry point of the SDK. It holds the configuration and
// the live session state, and exposes all of the Authenticity operations.
type Client struct {
	// OwnerID is the Authenticity owner identifier.
	OwnerID string
	// AppID is the Authenticity application identifier.
	AppID string
	// APIURL is the base URL ending with /api/v1/client.
	APIURL string
	// Version is the SDK/client version reported to the server.
	Version string
	// LicenseKey is the license key used for license-key based login.
	LicenseKey string
	// Session is the current authentication session (see Session).
	Session Session
	// AppData carries the application metadata from the last login.
	AppData AppData
	// Hwid is the generated hardware ID of this machine.
	Hwid string
	// Hash is a secondary machine fingerprint hash.
	Hash string
	// LastError holds the most recent error message, if any.
	LastError string

	// http is the shared HTTP client used for all requests.
	http *http.Client
}

// newHTTPClient builds a shared HTTP client with sane defaults.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: defaultTimeOut,
	}
}

// DefaultClientOptions is retained for API-surface parity with the other SDKs.
// The implementation uses a fixed request timeout which matches the other SDKs.
type DefaultClientOptions struct {
	// RequestTimeout is the HTTP request timeout used by the client.
	RequestTimeout time.Duration
}

// SetRequestTimeout overrides the HTTP client timeout on c. It takes effect for
// subsequent requests. A zero or negative value restores the default.
func (c *Client) SetRequestTimeout(d time.Duration) {
	if d <= 0 {
		c.http = newHTTPClient()
		return
	}
	c.http = &http.Client{Timeout: d}
}

// makeURL joins a relative endpoint path onto the client's base URL and
// validates the result.
func (c *Client) makeURL(endpoint string) (string, error) {
	base := c.APIURL
	if base == "" {
		return "", &url.Error{
			Op:  "parse",
			URL: endpoint,
			Err: errMissingBaseURL,
		}
	}
	// Ensure there is exactly one "/" between the base URL and the endpoint.
	trimmed := base
	for len(trimmed) > 0 && trimmed[len(trimmed)-1] == '/' {
		trimmed = trimmed[:len(trimmed)-1]
	}
	return trimmed + endpoint, nil
}

var errMissingBaseURL = &missingBaseURLError{}

type missingBaseURLError struct{}

func (e *missingBaseURLError) Error() string {
	return "authenticity: APIURL is not set"
}
