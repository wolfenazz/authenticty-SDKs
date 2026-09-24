package authenticity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestChatProfileAndMessageIdentity(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("request JSON: %v", err)
		}
		if body["token"] != "TOK" || body["appId"] != "APP" {
			t.Errorf("missing auth body: %v", body)
		}
		if r.Header.Get("Authorization") != "Bearer TOK" {
			t.Errorf("missing bearer token")
		}
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/chat/profile":
			if r.Method == "PUT" && (body["nickname"] != "مرحبا" || body["avatarId"] != "AVATAR_2") {
				t.Errorf("profile update fields: %v", body)
			}
			w.Write([]byte(`{"success":"true","profileId":"user-1","nickname":"مرحبا","avatarId":"AVATAR_2"}`))
		case "/chat/messages":
			w.Write([]byte(`{"success":"true","messages":[{"id":"m1","channelId":"general","senderId":"user-1","sender":"مرحبا","avatarId":"AVATAR_2","content":"**hi**","timeSent":"2026-01-01T00:00:00Z"}]}`))
		default:
			t.Errorf("unexpected route: %s", r.URL.Path)
		}
	}))
	defer server.Close()
	client := NewClient("owner", "APP", server.URL, "1")
	client.Session = Session{Token: "TOK", IsValid: true}
	profile, ok := client.GetChatProfile()
	if !ok || profile.ID != "user-1" {
		t.Fatalf("get profile: %+v, %v, %s", profile, ok, client.GetLastError())
	}
	profile, ok = client.UpdateChatProfile("مرحبا", "AVATAR_2")
	if !ok || profile.Nickname != "مرحبا" {
		t.Fatalf("update profile: %+v, %v", profile, ok)
	}
	messages := client.GetMessages("all")
	if len(messages) != 1 || messages[0].ChannelID != "general" || messages[0].SenderID != profile.ID || messages[0].AvatarID != "AVATAR_2" {
		t.Fatalf("messages: %+v", messages)
	}
	if len(calls) != 3 || calls[0] != "POST /chat/profile" || calls[1] != "PUT /chat/profile" || calls[2] != "POST /chat/messages" {
		t.Fatalf("calls: %v", calls)
	}
}

func TestGetBoolToleratesStrings(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{`{"success":"true"}`, true},
		{`{"success":"TRUE"}`, true},
		{`{"success":"1"}`, true},
		{`{"success":1}`, true},
		{`{"success":true}`, true},
		{`{"success":"false"}`, false},
		{`{"success":"0"}`, false},
		{`{"success":0}`, false},
		{`{"success":false}`, false},
		{`{}`, false},
	}
	for _, c := range cases {
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(c.raw), &m); err != nil {
			t.Fatal(err)
		}
		r := jsonResponse(m)
		if got := r.getBool("success", false); got != c.want {
			t.Errorf("getBool(%q) = %v, want %v", c.raw, got, c.want)
		}
	}
}

func TestRemainingBreakdownISO(t *testing.T) {
	c := &Client{}
	c.Session.Expiry = time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	y, mo, d, h, mi := c.remainingBreakdown()
	if y != 0 || mo != 0 || d < 1 || d > 2 {
		t.Errorf("expected ~2 days, got y=%d mo=%d d=%d h=%d mi=%d", y, mo, d, h, mi)
	}
}

func TestRemainingBreakdownNever(t *testing.T) {
	c := &Client{}
	c.Session.Expiry = "Never"
	y, mo, d, h, mi := c.remainingBreakdown()
	// "Never" is mapped to a far-future date (2099) → large breakdown.
	if y < 70 {
		t.Errorf("expected large years for Never, got y=%d mo=%d d=%d h=%d mi=%d", y, mo, d, h, mi)
	}
}
