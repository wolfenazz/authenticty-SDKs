package authenticity

// GetChannels fetches the list of available chat channels. It returns an empty
// slice (never nil) on failure.
func (c *Client) GetChannels() []Channel {
	if !c.sessionValid() {
		return []Channel{}
	}
	body := map[string]interface{}{
		"token": c.Session.Token,
		"appId": c.AppID,
	}
	resp, err := c.doJSONRequest(endpointChatChannels, body, true)
	if err != nil {
		return []Channel{}
	}
	arr := resp.getArray("channels")
	if arr == nil {
		c.setErr(resp.getString("message", "failed to fetch channels"))
		return []Channel{}
	}

	out := make([]Channel, 0, len(arr))
	for _, item := range arr {
		obj, ok := itemAsMap(item)
		if !ok {
			continue
		}
		out = append(out, Channel{
			ID:           obj.getString("id", ""),
			Name:         obj.getString("name", ""),
			CooldownUnit: obj.getString("cooldownUnit", obj.getString("cooldown_unit", "")),
			CooldownTime: obj.getInt("cooldownTime", obj.getInt("cooldown_time", 0)),
		})
	}
	c.setErr("")
	return out
}

// GetMessages fetches messages for a channel ("all" fetches messages from all
// channels). It returns an empty slice (never nil) on failure.
func (c *Client) GetMessages(channelID string) []Message {
	if !c.sessionValid() {
		return []Message{}
	}
	if channelID == "" {
		channelID = "all"
	}
	body := map[string]interface{}{
		"token":     c.Session.Token,
		"appId":     c.AppID,
		"channelId": channelID,
	}
	resp, err := c.doJSONRequest(endpointChatMessages, body, true)
	if err != nil {
		return []Message{}
	}
	arr := resp.getArray("messages")
	if arr == nil {
		c.setErr(resp.getString("message", "failed to fetch messages"))
		return []Message{}
	}

	out := make([]Message, 0, len(arr))
	for _, item := range arr {
		obj, ok := itemAsMap(item)
		if !ok {
			continue
		}
		out = append(out, Message{
			ID:        obj.getString("id", ""),
			ChannelID: obj.getString("channelId", ""),
			SenderID:  obj.getString("senderId", ""),
			Sender:    obj.getString("sender", obj.getString("author", "")),
			AvatarID:  obj.getString("avatarId", ""),
			Content:   obj.getString("content", obj.getString("text", "")),
			TimeSent:  obj.getString("timeSent", obj.getString("timestamp", obj.getString("time_sent", ""))),
		})
	}
	c.setErr("")
	return out
}

// GetChatProfile fetches the current user's nickname and avatar.
func (c *Client) GetChatProfile() (ChatProfile, bool) {
	if !c.sessionValid() {
		return ChatProfile{}, false
	}
	resp, err := c.doJSONRequest(endpointChatProfile, map[string]interface{}{
		"token": c.Session.Token, "appId": c.AppID,
	}, true)
	if err != nil {
		return ChatProfile{}, false
	}
	if !resp.getBool("success", false) {
		c.setErr(resp.getString("message", "failed to fetch chat profile"))
		return ChatProfile{}, false
	}
	c.setErr("")
	return ChatProfile{ID: resp.getString("profileId", ""), Nickname: resp.getString("nickname", ""), AvatarID: resp.getString("avatarId", "")}, true
}

// UpdateChatProfile changes the current user's nickname and application avatar ID.
func (c *Client) UpdateChatProfile(nickname, avatarID string) (ChatProfile, bool) {
	if !c.sessionValid() {
		return ChatProfile{}, false
	}
	resp, err := c.doJSONRequestMethod(endpointChatProfile, "PUT", map[string]interface{}{
		"token": c.Session.Token, "appId": c.AppID, "nickname": nickname, "avatarId": avatarID,
	}, true)
	if err != nil {
		return ChatProfile{}, false
	}
	if !resp.getBool("success", false) {
		c.setErr(resp.getString("message", "failed to update chat profile"))
		return ChatProfile{}, false
	}
	c.setErr("")
	return ChatProfile{ID: resp.getString("profileId", ""), Nickname: resp.getString("nickname", ""), AvatarID: resp.getString("avatarId", "")}, true
}

// SendMessage posts a new message to a channel. It returns true on success.
func (c *Client) SendMessage(channelID, content string) bool {
	if channelID == "" || content == "" {
		c.setErr("authenticity: channelId and content are required")
		return false
	}
	if !c.sessionValid() {
		return false
	}
	body := map[string]interface{}{
		"token":     c.Session.Token,
		"appId":     c.AppID,
		"channelId": channelID,
		"content":   content,
	}
	resp, err := c.doJSONRequestMethod(endpointChatMessages, "PUT", body, true)
	if err != nil {
		return false
	}
	// The PUT message-send response reports success; tolerate either key casing.
	ok := resp.getBool("success", false)
	if !ok {
		c.setErr(resp.getString("message", "failed to send message"))
		return false
	}
	c.setErr("")
	return true
}

// itemAsMap converts a decoded JSON element into a jsonResponse for tolerant
// field access. Returns ok=false when the element is not an object.
func itemAsMap(item interface{}) (jsonResponse, bool) {
	m, ok := item.(map[string]interface{})
	if !ok {
		return nil, false
	}
	return jsonResponse(m), true
}
