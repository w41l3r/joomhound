package output

import (
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/w41l3r/joomhound/internal/models"
)

func TestNewFormatterRejectsUnknownFormat(t *testing.T) {
	if _, err := NewFormatter("csv"); err == nil {
		t.Fatal("NewFormatter(csv) returned nil error")
	} else if !strings.Contains(err.Error(), "json, markdown, xml, text") {
		t.Fatalf("error does not list supported formats: %v", err)
	}

	formatter, err := NewFormatter(" JSON ")
	if err != nil {
		t.Fatalf("NewFormatter(JSON): %v", err)
	}
	if formatter.format != "json" {
		t.Fatalf("normalized format = %q, want json", formatter.format)
	}
}

func TestXMLReportContainsCompleteResult(t *testing.T) {
	result := &models.ScanResult{
		Target:           `https://target.example/joomla?a=1&b=<value>`,
		JoomlaDetected:   true,
		DetectionSignals: []string{"core-manifest", "meta-generator"},
		Version: models.VersionInfo{
			Detected: true, Version: "4.4.3", Methods: []string{"core-manifest"}, Confidence: 0.98,
		},
		Components: []models.Component{
			{Name: "com_content", Type: "component", Path: "/components/com_content/", Detected: true, Version: "4.0", Installed: true},
		},
		Templates: []models.Template{
			{Name: "cassiopeia", Path: "/templates/cassiopeia/", Version: "1.0"},
		},
		Plugins: []models.Plugin{
			{Name: "plg_system_example", Path: "/plugins/system/example/", Author: "Example & Co", Installed: true},
		},
		Users: []models.User{
			{Username: "admin", ID: 42, Email: "admin@example.test", Found: true, Method: "operator-supplied", PasswordValid: true, Password: `p&<secret>`, PasswordAttempts: 3, PasswordErrors: 1},
		},
		Vulnerabilities: []models.Vulnerability{
			{CVE: "CVE-2024-0001", Title: "Example <issue>", Description: "Details & impact", CVSS: 8.1,
				Severity: "HIGH", Affected: []string{"Joomla 4.4.3"}, PoC: "none", Reference: "https://example.test/one",
				References: []string{"https://example.test/one", "https://example.test/two"}, Source: "nvd+offline", Confidence: "high"},
		},
		Metadata: models.ScanMetadata{
			StartTime: "2026-09-10T10:00:00Z", EndTime: "2026-09-10T10:00:01Z", Duration: "1s",
			HTTPRequests: 12, HTTPErrors: 1, HTTPRetries: 2, RateLimitedHits: 3, BreakerTripped: 4,
			CredentialAttempts: 3, CredentialErrors: 1, CredentialsFound: 1,
			CVESource: "offline", Errors: []string{"one error"}, Warnings: []string{"one warning"},
		},
	}

	formatter, err := NewFormatter("xml")
	if err != nil {
		t.Fatalf("NewFormatter: %v", err)
	}
	report, err := formatter.Format(result)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	var root struct {
		XMLName xml.Name
	}
	if err := xml.Unmarshal([]byte(report), &root); err != nil {
		t.Fatalf("generated XML is invalid: %v\n%s", err, report)
	}
	if root.XMLName.Local != "scan" {
		t.Fatalf("root element = %q, want scan", root.XMLName.Local)
	}

	for _, want := range []string{
		"<joomla_detected>true</joomla_detected>",
		"<detection_signals>", "<version>", "<components>", "<templates>",
		"<plugins>", "<users>", "<password_valid>true</password_valid>",
		"<password_attempts>3</password_attempts>", "<password_errors>1</password_errors>",
		"<vulnerabilities>", "<references>", "<metadata>",
		"<rate_limited_hits>3</rate_limited_hits>",
		"<credential_attempts>3</credential_attempts>", "<credential_errors>1</credential_errors>",
		"<credentials_found>1</credentials_found>",
		"<errors>", "<warnings>",
		"a=1&amp;b=&lt;value&gt;", "p&amp;&lt;secret&gt;", "Example &amp; Co",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("XML report does not contain %q\n%s", want, report)
		}
	}
}

func TestXMLEmitsEmptyCollectionElements(t *testing.T) {
	formatter, err := NewFormatter("xml")
	if err != nil {
		t.Fatalf("NewFormatter: %v", err)
	}
	report, err := formatter.Format(&models.ScanResult{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	for _, want := range []string{
		"<components></components>", "<templates></templates>", "<plugins></plugins>",
		"<users></users>", "<vulnerabilities></vulnerabilities>",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("empty XML report does not contain %q\n%s", want, report)
		}
	}
}

func TestJSONReportIsMachineReadable(t *testing.T) {
	formatter, err := NewFormatter("json")
	if err != nil {
		t.Fatalf("NewFormatter: %v", err)
	}
	report, err := formatter.Format(&models.ScanResult{
		Target:  "https://target.example",
		Version: models.VersionInfo{Detected: true, Version: "5.2.0"},
	})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if !json.Valid([]byte(report)) {
		t.Fatalf("generated JSON is invalid:\n%s", report)
	}
	if !strings.Contains(report, `"target": "https://target.example"`) ||
		!strings.Contains(report, `"version": "5.2.0"`) {
		t.Fatalf("JSON report dropped core fields:\n%s", report)
	}
}

func TestHumanReportsIncludeCoreFindings(t *testing.T) {
	result := &models.ScanResult{
		Target:         "https://target.example",
		JoomlaDetected: true,
		Version: models.VersionInfo{
			Detected: true, Version: "4.4.3", Methods: []string{"core-manifest"}, Confidence: 0.98,
		},
		Components: []models.Component{
			{Name: "com_content", Type: "component", Path: "/components/com_content/", Detected: true},
		},
		Users: []models.User{
			{Username: "admin", Email: "admin@example.test", Found: true, Method: "operator-supplied", PasswordValid: true, Password: "secret", PasswordAttempts: 3},
			{Username: "editor", Found: true, Method: "public-api", PasswordAttempts: 19, PasswordErrors: 1},
		},
		Vulnerabilities: []models.Vulnerability{
			{CVE: "CVE-2024-0001", Title: "Example issue", CVSS: 8.1, Severity: "HIGH", Confidence: "high", Affected: []string{"Joomla 4.4.3"}, Reference: "https://example.test/advisory"},
		},
		Metadata: models.ScanMetadata{
			StartTime: "2026-09-11T00:00:00Z", Duration: "1s", HTTPRequests: 12,
			HTTPErrors: 1, HTTPRetries: 2, CredentialAttempts: 22, CredentialErrors: 1, CredentialsFound: 1, CVESource: "offline",
			Errors: []string{"one error"}, Warnings: []string{"one warning"},
		},
	}

	tests := []struct {
		format string
		want   []string
	}{
		{
			format: "text",
			want: []string{
				"Joomla Detected", "Version: 4.4.3", "com_content", "admin@example.test",
				"User: admin (operator-supplied)", "Valid credentials found after 3 attempts",
				"Password: secret", "User: editor (public-api)",
				"No valid password confirmed after 19 attempts (18 conclusive, 1 inconclusive)",
				"Credential Attempts: 22 (inconclusive: 1, valid credentials: 1)",
				"CVE-2024-0001", "one warning", "one error",
			},
		},
		{
			format: "markdown",
			want: []string{
				"# JoomHound Scan Report", "**Version:** 4.4.3", "com_content",
				"admin@example.test", "operator-supplied", "valid after 3 attempts",
				"no valid password confirmed (18 conclusive, 1 inconclusive)",
				"**Credential Attempts:** 22", "**Inconclusive Credential Checks:** 1",
				"CVE-2024-0001", "one warning", "one error",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.format, func(t *testing.T) {
			formatter, err := NewFormatter(tc.format)
			if err != nil {
				t.Fatalf("NewFormatter: %v", err)
			}
			report, err := formatter.Format(result)
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			for _, want := range tc.want {
				if !strings.Contains(report, want) {
					t.Errorf("%s report does not contain %q\n%s", tc.format, want, report)
				}
			}
		})
	}
}
