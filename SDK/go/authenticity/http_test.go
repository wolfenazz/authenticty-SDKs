package authenticity

import (
	"encoding/json"
	"testing"
	"time"
)

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
