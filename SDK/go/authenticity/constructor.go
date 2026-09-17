package authenticity

// NewClient creates a Client with the provided configuration. It initializes
// the shared HTTP client and generates the machine HWID and hash fingerprints.
//
// ownerID and appID identify the application within Authenticity. apiURL must
// already end with "/api/v1/client" (e.g.
// "https://your-domain.example/api/v1/client").
func NewClient(ownerID, appID, apiURL, version string) *Client {
	return &Client{
		OwnerID:   ownerID,
		AppID:     appID,
		APIURL:    apiURL,
		Version:   version,
		Hwid:      GenerateHwid(),
		Hash:      GenerateHash(),
		Session:   Session{IsValid: false},
		http:      newHTTPClient(),
	}
}

// ComputeHwid is a convenience wrapper for standalone HWID generation.
func ComputeHwid() string {
	return GenerateHwid()
}
