package authenticity

import "encoding/json"

// Login authenticates using the client's configured OwnerID, AppID and
// LicenseKey. It returns true on success and populates the Session and AppData.
func (c *Client) Login() bool {
	if c.LicenseKey == "" {
		c.setErr("authenticity: license key is empty")
		return false
	}
	body := map[string]interface{}{
		"ownerId":    c.OwnerID,
		"appId":      c.AppID,
		"licenseKey": c.LicenseKey,
		"hwid":       c.Hwid,
		"version":    c.Version,
		"hash":       c.Hash,
	}
	resp, err := c.doJSONRequest(endpointLogin, body, false)
	if err != nil {
		return false
	}
	return c.applyLoginResponse(resp)
}

// LoginWithCredentials authenticates a username/password pair against the
// server. The supplied credentials take precedence over any saved ones.
func (c *Client) LoginWithCredentials(username, password string) bool {
	if username == "" || password == "" {
		c.setErr("authenticity: username and password are required")
		return false
	}
	body := map[string]interface{}{
		"ownerId":  c.OwnerID,
		"appId":    c.AppID,
		"username": username,
		"password": password,
		"hwid":     c.Hwid,
		"version":  c.Version,
		"hash":     c.Hash,
	}
	resp, err := c.doJSONRequest(endpointLoginUser, body, false)
	if err != nil {
		return false
	}
	return c.applyLoginResponse(resp)
}

// CheckForUpdate checks the server version before login. It returns nil when
// the application cannot be resolved or the request fails.
func (c *Client) CheckForUpdate() *UpdateInfo {
	body := map[string]interface{}{
		"ownerId": c.OwnerID,
		"appId":   c.AppID,
		"version": c.Version,
	}
	resp, err := c.doJSONRequest(endpointAppUpdate, body, false)
	if err != nil || !resp.getBool("success", false) {
		if err == nil {
			c.setErr(resp.getString("message", "update check failed"))
		}
		return nil
	}
	return &UpdateInfo{
		UpdateRequired: resp.getBool("updateRequired", false),
		ClientVersion:  resp.getString("clientVersion", c.Version),
		CurrentVersion: resp.getString("currentVersion", ""),
		UpdateLink:     resp.getString("updateLink", ""),
		AppName:        resp.getString("appName", ""),
		AppStatus:      resp.getString("appStatus", ""),
	}
}

// Register creates a new user account on the server. It returns true only when
// the server responds with success == true.
func (c *Client) Register(username, password, licenseKey string) bool {
	if username == "" || password == "" {
		c.setErr("authenticity: username and password are required")
		return false
	}
	body := map[string]interface{}{
		"ownerId":    c.OwnerID,
		"appId":      c.AppID,
		"username":   username,
		"password":   password,
		"licenseKey": licenseKey,
		"hwid":       c.Hwid,
		"version":    c.Version,
		"hash":       c.Hash,
	}
	resp, err := c.doJSONRequest(endpointRegister, body, false)
	if err != nil {
		return false
	}
	ok := resp.getBool("success", false)
	if !ok {
		msg := resp.getString("message", "registration failed")
		c.setErr(msg)
	}
	return ok
}

// applyLoginResponse extracts the login response into the client's Session and
// AppData. The UpdateLink field is intentionally tolerant of the server not
// sending it (defaults to "").
func (c *Client) applyLoginResponse(resp jsonResponse) bool {
	ok := resp.getBool("success", false)
	if !ok {
		msg := resp.getString("message", "login failed")
		c.Session.UpdateLink = resp.getString("updateLink", "")
		c.setErr(msg)
		c.Session.IsValid = false
		return false
	}
	token := resp.getString("token", "")
	if token == "" {
		c.Session.IsValid = false
		c.Session.UpdateLink = resp.getString("updateLink", "")
		c.setErr("authenticity: login response did not include a session token")
		return false
	}

	c.Session = Session{
		Token:      token,
		Expiry:     resp.getString("expiry", ""),
		Username:   resp.getString("username", ""),
		IP:         resp.getString("ip", ""),
		Hwid:       resp.getString("hwid", c.Hwid),
		Level:      resp.getInt("level", 0),
		SubscriptionID: resp.getString("subscriptionId", ""),
		SubscriptionName: resp.getString("subscriptionName", ""),
		Features:   responseFeatures(resp),
		Limits:     responseLimits(resp),
		IsValid:    true,
		UpdateLink: resp.getString("updateLink", ""),
	}
	c.AppData = AppData{
		Name:     resp.getString("appName", ""),
		Version:  resp.getString("appVersion", ""),
		Status:   resp.getString("appStatus", ""),
		HwidLock: resp.getBool("hwidLock", false),
	}
	c.setErr("")
	return true
}

// CheckSession performs a heartbeat against the /auth/check endpoint. It
// returns true while the session is valid. When the server reports the license
// or session as expired, the session is invalidated and an appropriate error is
// recorded.
func (c *Client) CheckSession() bool {
	if !c.Session.IsValid || c.Session.Token == "" {
		c.Session.IsValid = false
		c.setErr("authenticity: not logged in")
		return false
	}
	body := map[string]interface{}{
		"token": c.Session.Token,
		"appId": c.AppID,
		"hwid":  c.Hwid,
	}
	resp, err := c.doJSONRequest(endpointCheck, body, true)
	if err != nil {
		return false
	}
	ok := resp.getBool("success", false)
	if ok {
		c.Session.IsValid = true
		c.applySubscriptionResponse(resp)
		c.setErr("")
		return true
	}

	// On failure the server may include expired=true and a reason.
	c.Session.IsValid = false
	expired := resp.getBool("expired", false)
	reason := resp.getString("reason", resp.getString("message", ""))
	switch {
	case expired && reason != "":
		c.setErr("authenticity: session expired: " + reason)
	case expired:
		c.setErr("authenticity: session expired")
	case reason != "":
		c.setErr("authenticity: check failed: " + reason)
	default:
		c.setErr("authenticity: session check failed")
	}
	return false
}

func responseFeatures(resp jsonResponse) []string {
	values := resp.getArray("features")
	features := make([]string, 0, len(values))
	for _, value := range values {
		if feature, ok := value.(string); ok { features = append(features, feature) }
	}
	return features
}

func responseLimits(resp jsonResponse) map[string]int {
	limits := make(map[string]int)
	values, ok := resp["limits"].(map[string]interface{})
	if !ok { return limits }
	for key, value := range values {
		switch number := value.(type) {
		case float64: if number >= 0 { limits[key] = int(number) }
		case int: if number >= 0 { limits[key] = number }
		case json.Number: if n, err := number.Int64(); err == nil && n >= 0 { limits[key] = int(n) }
		}
	}
	return limits
}

func (c *Client) applySubscriptionResponse(resp jsonResponse) {
	if _, ok := resp["subscriptionId"]; ok { c.Session.SubscriptionID = resp.getString("subscriptionId", "") }
	if _, ok := resp["subscriptionName"]; ok { c.Session.SubscriptionName = resp.getString("subscriptionName", "") }
	if _, ok := resp["level"]; ok { c.Session.Level = resp.getInt("level", c.Session.Level) }
	if _, ok := resp["features"]; ok { c.Session.Features = responseFeatures(resp) }
	if _, ok := resp["limits"]; ok { c.Session.Limits = responseLimits(resp) }
}

// HasFeature asks the server to authorize a named feature for this session.
// A denied feature does not invalidate the session.
func (c *Client) HasFeature(feature string) bool {
	if feature == "" || !c.Session.IsValid || c.Session.Token == "" { return false }
	resp, err := c.doJSONRequest(endpointCheck, map[string]interface{}{
		"token": c.Session.Token, "appId": c.AppID, "hwid": c.Hwid, "feature": feature,
	}, true)
	if err != nil || !resp.getBool("success", false) { return false }
	c.applySubscriptionResponse(resp)
	return true
}

// CheckBlacklist reports whether the current hardware is blacklisted. The
// server returns success == true when the HWID is NOT blacklisted. This method
// returns true when the machine IS blacklisted (mirroring the other SDKs).
func (c *Client) CheckBlacklist() bool {
	body := map[string]interface{}{
		"ownerId": c.OwnerID,
		"appId":   c.AppID,
		"hwid":    c.Hwid,
	}
	resp, err := c.doJSONRequest(endpointCheckBlacklist, body, false)
	if err != nil {
		return false
	}
	ok := resp.getBool("success", false)
	if ok {
		// success == true means NOT blacklisted.
		c.setErr("")
		return false
	}
	// Server reported the HWID as blacklisted.
	msg := resp.getString("message", "hardware is blacklisted")
	c.setErr(msg)
	return true
}

// Ban revokes the current session by reporting an abuse reason to the server.
// On success the local session is invalidated. It returns true on success.
func (c *Client) Ban(reason string) bool {
	if !c.Session.IsValid || c.Session.Token == "" {
		c.setErr("authenticity: not logged in")
		return false
	}
	body := map[string]interface{}{
		"token":  c.Session.Token,
		"appId":  c.AppID,
		"reason": reason,
	}
	resp, err := c.doJSONRequest(endpointBan, body, true)
	if err != nil {
		return false
	}
	ok := resp.getBool("success", false)
	c.Session.IsValid = false
	if !ok {
		c.setErr(resp.getString("message", "ban request failed"))
		return false
	}
	c.setErr("")
	return true
}

// setErr records the last error message on the client.
func (c *Client) setErr(msg string) {
	c.LastError = msg
}
