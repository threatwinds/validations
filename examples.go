package validations

type Entity struct {
	Type         string                 `json:"type"  example:"object"`
	Attributes   map[string]interface{} `json:"attributes"`
	Associations []Entity               `json:"associations"`
	Reputation   int                    `json:"reputation" example:"-1"`
	Correlate    []string               `json:"correlate"`
	Tags         []string               `json:"tags"`
	VisibleBy    []string               `json:"visibleBy"`
}

var eMalware = Entity{
	Type: "malware",
	Attributes: map[string]interface{}{
		"malware":        "pdf dropper agent",
		"malware-family": "pdf",
		"malware-type":   "dropper",
	},
	Correlate:  []string{"malware-family", "malware-type"},
	Reputation: -3,
}

var eFile = Entity{
	Type:       "file",
	Reputation: -3,
	Attributes: map[string]interface{}{
		"file":     "21a1610ce915d5d5a8ab5b1f5b6d6715cf4f4e3bc0c868352a175279b1881afe",
		"md5":      "fb92636db83298a4215a2f5ffa2527b1",
		"sha1":     "93a8f022b553f786bf077ff55616350727f8764a",
		"sha256":   "202492bdd391deac6c1e72eba9d039a7c60bcc61f1afa0d85269d8c4c5af1284",
		"sha3-256": "21a1610ce915d5d5a8ab5b1f5b6d6715cf4f4e3bc0c868352a175279b1881afe",
	},
	Associations: []Entity{eMalware},
	Tags:         []string{"malware", "common-file"},
	Correlate:    []string{"md5", "sha1", "sha256", "sha3-256"},
}
