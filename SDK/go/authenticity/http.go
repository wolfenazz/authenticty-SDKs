package authenticity

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// jsonResponse is a tolerant wrapper around a decoded JSON object. It lets the
// SDK read fields without panicking when keys or types are missing.
type jsonResponse map[string]interface{}

// getString returns the string value for key, or def when missing/unusable.
func (r jsonResponse) getString(key, def string) string {
	if v, ok := r[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}

// getBool returns the boolean value for key, or def when missing/unusable.
//
// The server returns `success` as the string "true"/"false" in most
// responses and as a real boolean in a few, so all of these are tolerated:
// the boolean true/false, the strings "true"/"false" (any casing) / "1"/"0",
// and the numbers 1/0.
func (r jsonResponse) getBool(key string, def bool) bool {
	v, ok := r[key]
	if !ok {
		return def
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		s := strings.TrimSpace(t)
		switch strings.ToLower(s) {
		case "true", "1":
			return true
		case "false", "0", "":
			return false
		}
	case float64:
		return t == 1
	case json.Number:
		n, err := t.Int64()
		if err == nil {
			return n == 1
		}
	}
	return def
}

// getInt returns the integer value for key, or def when missing/unusable.
func (r jsonResponse) getInt(key string, def int) int {
	if v, ok := r[key]; ok {
		switch t := v.(type) {
		case float64:
			return int(t)
		case int:
			return t
		case json.Number:
			n, err := t.Int64()
			if err == nil {
				return int(n)
			}
		}
	}
	return def
}

// getArray returns the value for key as a slice of raw JSON values, or nil.
func (r jsonResponse) getArray(key string) []interface{} {
	if v, ok := r[key]; ok {
		if arr, ok := v.([]interface{}); ok {
			return arr
		}
	}
	return nil
}

// decodeJSONResponse reads the entire body and attempts to parse it as a JSON
// object. It tolerates empty bodies and unparseable content. lenient parsing is
// used so that numbers decode to float64/json.Number as appropriate.
func decodeJSONResponse(body io.Reader) (jsonResponse, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return jsonResponse{}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var out map[string]interface{}
	if err := dec.Decode(&out); err != nil {
		// Tolerate trailing content by attempting a streaming parse; if that
		// also fails return what we have as an empty response.
		out = nil
	}
	return jsonResponse(out), nil
}

// doJSONRequest preserves the SDK's default POST behavior.
func (c *Client) doJSONRequest(endpoint string, body map[string]interface{}, authorized bool) (jsonResponse, error) {
	return c.doJSONRequestMethod(endpoint, http.MethodPost, body, authorized)
}

// doJSONRequestMethod performs a JSON request with the requested HTTP method
// and returns the parsed JSON response. It keeps structured 4xx responses
// available to callers so they can surface server messages.
func (c *Client) doJSONRequestMethod(endpoint, method string, body map[string]interface{}, authorized bool) (jsonResponse, error) {
	u, err := c.makeURL(endpoint)
	if err != nil {
		c.setErr(err.Error())
		return nil, err
	}

	payload, err := json.Marshal(body)
	if err != nil {
		c.setErr("authenticity: failed to marshal request body: " + err.Error())
		return nil, err
	}

	req, err := http.NewRequest(method, u, bytes.NewReader(payload))
	if err != nil {
		c.setErr("authenticity: failed to build request: " + err.Error())
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if authorized && c.Session.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Session.Token)
	}

	client := c.http
	if client == nil {
		client = newHTTPClient()
	}

	resp, err := client.Do(req)
	if err != nil {
		c.setErr("authenticity: network error: " + err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	// Read and parse the body regardless of status code; the server returns
	// structured JSON bodies even on 4xx errors.
	parsed, perr := decodeJSONResponse(resp.Body)
	if perr != nil {
		c.setErr("authenticity: failed to read response: " + perr.Error())
		return parsed, perr
	}

	// Surface non-2xx status as an error message but keep the parsed body so
	// callers can extract business fields (e.g. expiry/reason).
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := parsed.getString("message", "")
		if msg == "" {
			msg = "HTTP status " + http.StatusText(resp.StatusCode)
		}
		c.setErr(msg)
		return parsed, nil
	}
	c.setErr("")
	return parsed, nil
}

// doGET performs a plain GET request (used for file downloads) and returns the
// raw body bytes. Redirects are followed automatically by the HTTP client.
func (c *Client) doGET(rawURL string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		c.setErr("authenticity: failed to build download request: " + err.Error())
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)

	client := c.http
	if client == nil {
		client = newHTTPClient()
	}

	resp, err := client.Do(req)
	if err != nil {
		c.setErr("authenticity: download network error: " + err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		c.setErr("authenticity: failed to read download body: " + err.Error())
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := "download returned HTTP " + http.StatusText(resp.StatusCode)
		snippet := strings.TrimSpace(string(data))
		if snippet != "" && len(snippet) < 256 {
			msg += ": " + snippet
		}
		c.setErr(msg)
		return nil, &httpStatusError{status: resp.StatusCode}
	}
	c.setErr("")
	return data, nil
}

// httpStatusError wraps a non-2xx HTTP status from a raw download.
type httpStatusError struct {
	status int
}

func (e *httpStatusError) Error() string {
	return "authenticity: unexpected HTTP status " + http.StatusText(e.status)
}
