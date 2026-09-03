package models

type ScanResult struct {
	Target           string
	JoomlaDetected   bool
	Version          VersionInfo
	Components       []Component
	Templates        []Template
	Plugins          []Plugin
	Users            []User
	Vulnerabilities  []Vulnerability
	Metadata         ScanMetadata
}

type VersionInfo struct {
	Detected    bool
	Version     string
	Methods     []string // methods used for detection
	Confidence  float64  // 0.0 to 1.0
}

type Component struct {
	Name      string
	Type      string // component, module, plugin
	Path      string
	Detected  bool
	Version   string
	Installed bool
}

type Template struct {
	Name    string
	Path    string
	Version string
}

type Plugin struct {
	Name      string
	Path      string
	Version   string
	Author    string
	Installed bool
}

type User struct {
	Username string
	ID       int
	Email    string
	Found    bool
	// For brute-force
	PasswordValid bool
	Password      string
}

type Vulnerability struct {
	CVE         string
	Title       string
	Description string
	CVSS        float64
	Affected    []string // versions/components affected
	PoC         string
	Reference   string
}

type ScanMetadata struct {
	StartTime    string
	EndTime      string
	Duration     string
	HTTPRequests int
	Errors       []string
}
