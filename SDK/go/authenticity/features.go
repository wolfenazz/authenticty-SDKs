package authenticity

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
)

// GetVariable fetches the value of a server-side variable. It returns the value
// or an empty string on failure (recording the error on the client).
func (c *Client) GetVariable(name string) string {
	if name == "" {
		c.setErr("authenticity: variable name is required")
		return ""
	}
	if !c.sessionValid() {
		return ""
	}
	body := map[string]interface{}{
		"token": c.Session.Token,
		"appId": c.AppID,
		"name":  name,
	}
	resp, err := c.doJSONRequest(endpointVarsGet, body, true)
	if err != nil {
		return ""
	}
	if !resp.getBool("success", false) {
		c.setErr(resp.getString("message", "failed to fetch variable "+name))
		return ""
	}
	c.setErr("")
	return resp.getString("value", "")
}

// DownloadFile fetches a file's metadata from the server, obtains the download
// URL, and then performs a separate GET to retrieve the raw bytes. It returns
// the file contents or an error.
func (c *Client) DownloadFile(fileID string) ([]byte, error) {
	if fileID == "" {
		c.setErr("authenticity: fileId is required")
		return nil, fmt.Errorf("authenticity: fileId is required")
	}
	if !c.sessionValid() {
		return nil, fmt.Errorf("%s", c.LastError)
	}
	body := map[string]interface{}{
		"token":  c.Session.Token,
		"appId":  c.AppID,
		"fileId": fileID,
	}
	resp, err := c.doJSONRequest(endpointFilesDownload, body, true)
	if err != nil {
		return nil, err
	}
	if !resp.getBool("success", false) {
		msg := resp.getString("message", "failed to fetch download url")
		c.setErr(msg)
		return nil, fmt.Errorf("%s", msg)
	}
	url := resp.getString("downloadUrl", "")
	if url == "" {
		url = resp.getString("url", "")
	}
	if url == "" {
		c.setErr("authenticity: file download url is empty")
		return nil, fmt.Errorf("authenticity: file download url is empty")
	}
	data, err := c.doGET(url)
	if err != nil {
		return nil, err
	}
	c.setErr("")
	return data, nil
}

// DownloadFileDirect resolves the file download URL and opens it in the user's
// default browser using a platform command. It returns true when the browser
// was successfully invoked.
func (c *Client) DownloadFileDirect(fileID string) bool {
	if fileID == "" {
		c.setErr("authenticity: fileId is required")
		return false
	}
	if !c.sessionValid() {
		return false
	}
	body := map[string]interface{}{
		"token":  c.Session.Token,
		"appId":  c.AppID,
		"fileId": fileID,
	}
	resp, err := c.doJSONRequest(endpointFilesDownload, body, true)
	if err != nil {
		return false
	}
	if !resp.getBool("success", false) {
		c.setErr(resp.getString("message", "failed to fetch download url"))
		return false
	}
	url := resp.getString("downloadUrl", "")
	if url == "" {
		url = resp.getString("url", "")
	}
	if url == "" {
		c.setErr("authenticity: file download url is empty")
		return false
	}
	if err := openURL(url); err != nil {
		c.setErr("authenticity: failed to open url: " + err.Error())
		return false
	}
	c.setErr("")
	return true
}

// openURL launches the platform's default browser handler for the given URL.
func openURL(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}

// TriggerWebhook fires a named webhook with arbitrary data on the server. It
// returns true when the server acknowledges success.
func (c *Client) TriggerWebhook(name string, data map[string]interface{}) bool {
	if name == "" {
		c.setErr("authenticity: webhook name is required")
		return false
	}
	if !c.sessionValid() {
		return false
	}
	if data == nil {
		data = map[string]interface{}{}
	}
	encodedData, err := json.Marshal(data)
	if err != nil {
		c.setErr("authenticity: failed to encode webhook data")
		return false
	}
	body := map[string]interface{}{
		"token":       c.Session.Token,
		"appId":       c.AppID,
		"webhookName": name,
		"data":        string(encodedData),
	}
	resp, err := c.doJSONRequest(endpointWebhook, body, true)
	if err != nil {
		return false
	}
	ok := resp.getBool("success", false)
	if !ok {
		c.setErr(resp.getString("message", "webhook trigger failed"))
		return false
	}
	c.setErr("")
	return true
}

// Log sends a log entry to the server. It is a no-op unless the session is
// valid. The type parameter defaults to "info" when empty.
func (c *Client) Log(data, logType string) {
	if !c.sessionValid() {
		return
	}
	if logType == "" {
		logType = "info"
	}
	body := map[string]interface{}{
		"token": c.Session.Token,
		"appId": c.AppID,
		"data":  data,
		"type":  logType,
	}
	resp, err := c.doJSONRequest(endpointLogsAdd, body, true)
	if err != nil {
		return
	}
	_ = resp
	c.setErr("")
}

// sessionValid reports whether a token exists and the session is marked valid.
func (c *Client) sessionValid() bool {
	if c.Session.Token == "" || !c.Session.IsValid {
		c.setErr("authenticity: not logged in or session invalid")
		return false
	}
	return true
}
