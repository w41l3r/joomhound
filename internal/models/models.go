package models

// ScanResult is the complete output of a scan.
//
// Every field carries an explicit JSON tag: without them the JSON report used
// Go field names, so downstream tooling broke whenever a field was renamed.
type ScanResult struct {
	Target         string `json:"target"`
	JoomlaDetected bool   `json:"joomla_detected"`
	// DetectionSignals lists which fingerprints fired, so a reader can judge
	// the strength of the detection instead of trusting a bare boolean.
	DetectionSignals []string        `json:"detection_signals,omitempty"`
	Version          VersionInfo     `json:"version"`
	Components       []Component     `json:"components"`
	Templates        []Template      `json:"templates"`
	Plugins          []Plugin        `json:"plugins,omitempty"`
	Users            []User          `json:"users"`
	Vulnerabilities  []Vulnerability `json:"vulnerabilities"`
	Metadata         ScanMetadata    `json:"metadata"`
}

type VersionInfo struct {
	Detected   bool     `json:"detected"`
	Version    string   `json:"version,omitempty"`
	Methods    []string `json:"methods,omitempty"`    // methods used for detection
	Confidence float64  `json:"confidence,omitempty"` // 0.0 to 1.0
}

type Component struct {
	Name      string `json:"name"`
	Type      string `json:"type"` // component, module, plugin
	Path      string `json:"path"`
	Detected  bool   `json:"detected"`
	Version   string `json:"version,omitempty"`
	Installed bool   `json:"installed"`
}

type Template struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Version string `json:"version,omitempty"`
}

type Plugin struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Version   string `json:"version,omitempty"`
	Author    string `json:"author,omitempty"`
	Installed bool   `json:"installed"`
}

type User struct {
	Username string `json:"username"`
	ID       int    `json:"id,omitempty"`
	Email    string `json:"email,omitempty"`
	Found    bool   `json:"found"`
	// Method records which enumeration technique confirmed this user, so a
	// report can state the evidence rather than just asserting existence.
	Method        string `json:"method,omitempty"`
	PasswordValid bool   `json:"password_valid"`
	Password      string `json:"password,omitempty"`
	// PasswordAttempts counts password candidates processed for this user.
	PasswordAttempts int `json:"password_attempts,omitempty"`
	// PasswordErrors counts processed candidates whose result was inconclusive
	// because a request failed.
	PasswordErrors int `json:"password_errors,omitempty"`
}

type Vulnerability struct {
	CVE         string   `json:"cve"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	CVSS        float64  `json:"cvss"`
	Severity    string   `json:"severity,omitempty"`
	Affected    []string `json:"affected,omitempty"` // versions/components affected
	PoC         string   `json:"poc,omitempty"`
	Reference   string   `json:"reference,omitempty"`
	References  []string `json:"references,omitempty"`
	// Source records where the record came from: "offline", "nvd", "github".
	Source string `json:"source,omitempty"`
	// Confidence reflects how sure we are the target is actually affected.
	// Version-range matches are high; component-name matches are lower.
	Confidence string `json:"confidence,omitempty"`
}

// SeverityOrDerived returns the stored severity label, deriving one from the
// CVSS score when the source did not provide it.
func (v Vulnerability) SeverityOrDerived() string {
	if v.Severity != "" {
		return v.Severity
	}
	switch {
	case v.CVSS >= 9.0:
		return "CRITICAL"
	case v.CVSS >= 7.0:
		return "HIGH"
	case v.CVSS >= 4.0:
		return "MEDIUM"
	case v.CVSS > 0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

type ScanMetadata struct {
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time"`
	Duration  string `json:"duration"`
	// HTTPRequests is now actually populated from the HTTP client's counters.
	HTTPRequests    int `json:"http_requests"`
	HTTPErrors      int `json:"http_errors"`
	HTTPRetries     int `json:"http_retries"`
	RateLimitedHits int `json:"rate_limited_hits"`
	BreakerTripped  int `json:"circuit_breaker_tripped"`
	// CredentialAttempts counts password candidates processed across all users.
	CredentialAttempts int `json:"credential_attempts"`
	// CredentialErrors counts candidate checks that were inconclusive because a
	// request failed.
	CredentialErrors int `json:"credential_errors"`
	// CredentialsFound counts users for whom a submitted password was valid.
	CredentialsFound int      `json:"credentials_found"`
	CVESource        string   `json:"cve_source,omitempty"`
	Errors           []string `json:"errors,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
}
