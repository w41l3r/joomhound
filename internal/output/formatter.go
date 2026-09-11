package output

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/w41l3r/joomhound/internal/models"
)

type Formatter struct {
	format string // json, xml, markdown, text
}

// NormalizeFormat validates and canonicalizes a report format.
func NormalizeFormat(format string) (string, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		return "text", nil
	}
	for _, supported := range GetFormatList() {
		if format == supported {
			return format, nil
		}
	}
	return "", fmt.Errorf("unsupported output format %q; choose one of: %s",
		format, strings.Join(GetFormatList(), ", "))
}

// NewFormatter returns a formatter only for a supported output format.
func NewFormatter(format string) (*Formatter, error) {
	normalized, err := NormalizeFormat(format)
	if err != nil {
		return nil, err
	}
	return &Formatter{format: normalized}, nil
}

// Format formats the scan result based on the configured format
func (f *Formatter) Format(result *models.ScanResult) (string, error) {
	switch f.format {
	case "json":
		return f.toJSON(result)
	case "xml":
		return f.toXML(result)
	case "markdown":
		return f.toMarkdown(result)
	case "text":
		return f.toText(result)
	default:
		return "", fmt.Errorf("unsupported output format %q", f.format)
	}
}

// toJSON converts result to JSON format
func (f *Formatter) toJSON(result *models.ScanResult) (string, error) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// toMarkdown converts result to Markdown format
func (f *Formatter) toMarkdown(result *models.ScanResult) (string, error) {
	var sb strings.Builder

	sb.WriteString("# JoomHound Scan Report\n\n")
	sb.WriteString(fmt.Sprintf("**Target:** %s\n\n", result.Target))
	sb.WriteString(fmt.Sprintf("**Scan Time:** %s\n\n", result.Metadata.StartTime))

	// Joomla Detection
	sb.WriteString("## Detection\n\n")
	if result.JoomlaDetected {
		sb.WriteString("✅ **Joomla Detected**\n\n")
	} else {
		sb.WriteString("❌ **Joomla Not Detected**\n\n")
	}

	// Version Information
	sb.WriteString("### Version\n\n")
	if result.Version.Detected {
		sb.WriteString(fmt.Sprintf("- **Version:** %s\n", result.Version.Version))
		sb.WriteString(fmt.Sprintf("- **Confidence:** %.0f%%\n", result.Version.Confidence*100))
		sb.WriteString(fmt.Sprintf("- **Detection Methods:** %s\n\n", strings.Join(result.Version.Methods, ", ")))
	} else {
		sb.WriteString("- Version not detected\n\n")
	}

	// Components
	sb.WriteString("### Components\n\n")
	if len(result.Components) > 0 {
		sb.WriteString("| Component | Type | Path | Status |\n")
		sb.WriteString("|-----------|------|------|--------|\n")
		for _, comp := range result.Components {
			status := "❌"
			if comp.Detected {
				status = "✅"
			}
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
				comp.Name, comp.Type, comp.Path, status))
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("No components detected.\n\n")
	}

	// Users and credential testing
	sb.WriteString("### Users and Credential Testing\n\n")
	if len(result.Users) > 0 {
		sb.WriteString("| Username | Email | Source | Credential Result |\n")
		sb.WriteString("|----------|-------|--------|-------------------|\n")
		for _, user := range result.Users {
			source := user.Method
			if source == "" {
				source = "unknown"
			}
			conclusive, inconclusive := credentialCheckCounts(user)
			credentialResult := "not tested"
			switch {
			case user.PasswordValid && inconclusive > 0:
				credentialResult = fmt.Sprintf("valid after %d attempts (%d inconclusive)",
					user.PasswordAttempts, inconclusive)
			case user.PasswordValid:
				credentialResult = fmt.Sprintf("valid after %d attempts", user.PasswordAttempts)
			case user.PasswordAttempts > 0 && inconclusive > 0:
				credentialResult = fmt.Sprintf("no valid password confirmed (%d conclusive, %d inconclusive)",
					conclusive, inconclusive)
			case user.PasswordAttempts > 0:
				credentialResult = fmt.Sprintf("no match after %d attempts", user.PasswordAttempts)
			}
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
				user.Username, user.Email, source, credentialResult))
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("No users recorded.\n\n")
	}

	// Vulnerabilities
	sb.WriteString("### Vulnerabilities\n\n")
	if len(result.Vulnerabilities) > 0 {
		sb.WriteString("| CVE | Title | CVSS | Status |\n")
		sb.WriteString("|-----|-------|------|--------|\n")
		for _, vuln := range result.Vulnerabilities {
			sb.WriteString(fmt.Sprintf("| %s | %s | %.1f | - |\n",
				vuln.CVE, vuln.Title, vuln.CVSS))
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("No vulnerabilities detected.\n\n")
	}

	// Metadata
	sb.WriteString("## Metadata\n\n")
	sb.WriteString(fmt.Sprintf("- **Duration:** %s\n", result.Metadata.Duration))
	sb.WriteString(fmt.Sprintf("- **HTTP Requests:** %d\n", result.Metadata.HTTPRequests))
	sb.WriteString(fmt.Sprintf("- **Credential Attempts:** %d\n", result.Metadata.CredentialAttempts))
	sb.WriteString(fmt.Sprintf("- **Inconclusive Credential Checks:** %d\n", result.Metadata.CredentialErrors))
	sb.WriteString(fmt.Sprintf("- **Valid Credentials:** %d\n", result.Metadata.CredentialsFound))

	if len(result.Metadata.Warnings) > 0 {
		sb.WriteString("\n### Warnings\n\n")
		for _, warning := range result.Metadata.Warnings {
			sb.WriteString(fmt.Sprintf("- %s\n", warning))
		}
	}

	if len(result.Metadata.Errors) > 0 {
		sb.WriteString("\n### Errors\n\n")
		for _, err := range result.Metadata.Errors {
			sb.WriteString(fmt.Sprintf("- %s\n", err))
		}
	}

	return sb.String(), nil
}

// toText converts result to plain text format
func (f *Formatter) toText(result *models.ScanResult) (string, error) {
	var sb strings.Builder

	sb.WriteString("================================\n")
	sb.WriteString("       JOOMHOUND SCAN REPORT     \n")
	sb.WriteString("================================\n\n")

	sb.WriteString(fmt.Sprintf("Target: %s\n", result.Target))
	sb.WriteString(fmt.Sprintf("Scan Time: %s\n", result.Metadata.StartTime))

	// Joomla Detection
	sb.WriteString("\n[*] Joomla Detection\n")
	if result.JoomlaDetected {
		sb.WriteString("    [+] Joomla Detected\n")
	} else {
		sb.WriteString("    [-] Joomla Not Detected\n")
	}

	// Version
	sb.WriteString("\n[*] Version Information\n")
	if result.Version.Detected {
		sb.WriteString(fmt.Sprintf("    [+] Version: %s\n", result.Version.Version))
		sb.WriteString(fmt.Sprintf("    [+] Confidence: %.0f%%\n", result.Version.Confidence*100))
		sb.WriteString(fmt.Sprintf("    [+] Methods: %s\n", strings.Join(result.Version.Methods, ", ")))
	} else {
		sb.WriteString("    [-] Version not detected\n")
	}

	// Components
	sb.WriteString("\n[*] Components\n")
	if len(result.Components) > 0 {
		for _, comp := range result.Components {
			if comp.Detected {
				sb.WriteString(fmt.Sprintf("    [+] %s (%s) - %s\n", comp.Name, comp.Type, comp.Path))
			}
		}
	} else {
		sb.WriteString("    [-] No components detected\n")
	}

	// Users and credential testing
	sb.WriteString("\n[*] Users and Credential Testing\n")
	if len(result.Users) > 0 {
		for _, user := range result.Users {
			source := user.Method
			if source == "" {
				source = "unknown source"
			}
			marker := "[-]"
			if user.Found {
				marker = "[+]"
			}
			sb.WriteString(fmt.Sprintf("    %s User: %s (%s)\n", marker, user.Username, source))
			if user.Email != "" {
				sb.WriteString(fmt.Sprintf("        Email: %s\n", user.Email))
			}
			conclusive, inconclusive := credentialCheckCounts(user)
			switch {
			case user.PasswordValid:
				sb.WriteString(fmt.Sprintf("        [+] Valid credentials found after %d attempts\n", user.PasswordAttempts))
				if inconclusive > 0 {
					sb.WriteString(fmt.Sprintf("        [!] Inconclusive password checks: %d\n", inconclusive))
				}
				sb.WriteString(fmt.Sprintf("        Password: %s\n", user.Password))
			case user.PasswordAttempts > 0 && inconclusive > 0:
				sb.WriteString(fmt.Sprintf(
					"        [!] No valid password confirmed after %d attempts (%d conclusive, %d inconclusive)\n",
					user.PasswordAttempts, conclusive, inconclusive))
			case user.PasswordAttempts > 0:
				sb.WriteString(fmt.Sprintf("        [-] No valid password found after %d attempts\n", user.PasswordAttempts))
			default:
				sb.WriteString("        [.] Passwords not tested\n")
			}
		}
	} else {
		sb.WriteString("    [-] No users recorded\n")
	}

	// Vulnerabilities. The text formatter previously omitted this section
	// entirely, so `-o report.txt` silently dropped every CVE finding.
	sb.WriteString("\n[*] Vulnerabilities\n")
	if len(result.Vulnerabilities) > 0 {
		for _, v := range result.Vulnerabilities {
			sb.WriteString(fmt.Sprintf("    [!] %s  CVSS %.1f (%s)\n", v.CVE, v.CVSS, v.SeverityOrDerived()))
			if v.Title != "" {
				sb.WriteString(fmt.Sprintf("        %s\n", v.Title))
			}
			if v.Confidence != "" {
				sb.WriteString(fmt.Sprintf("        Confidence: %s\n", v.Confidence))
			}
			if len(v.Affected) > 0 {
				sb.WriteString(fmt.Sprintf("        Affected: %s\n", strings.Join(v.Affected, ", ")))
			}
			if v.Reference != "" {
				sb.WriteString(fmt.Sprintf("        Ref: %s\n", v.Reference))
			}
		}
	} else {
		sb.WriteString("    [-] No vulnerabilities correlated\n")
	}

	// Metadata
	sb.WriteString("\n[*] Statistics\n")
	sb.WriteString(fmt.Sprintf("    [+] Duration: %s\n", result.Metadata.Duration))
	sb.WriteString(fmt.Sprintf("    [+] HTTP Requests: %d (errors: %d, retries: %d)\n",
		result.Metadata.HTTPRequests, result.Metadata.HTTPErrors, result.Metadata.HTTPRetries))
	sb.WriteString(fmt.Sprintf("    [+] Credential Attempts: %d (inconclusive: %d, valid credentials: %d)\n",
		result.Metadata.CredentialAttempts, result.Metadata.CredentialErrors,
		result.Metadata.CredentialsFound))
	if result.Metadata.CVESource != "" {
		sb.WriteString(fmt.Sprintf("    [+] CVE Source: %s\n", result.Metadata.CVESource))
	}
	if result.Metadata.BreakerTripped > 0 {
		sb.WriteString(fmt.Sprintf("    [!] Circuit breaker tripped %d time(s) - results may be incomplete\n",
			result.Metadata.BreakerTripped))
	}

	if len(result.Metadata.Warnings) > 0 {
		sb.WriteString("\n[*] Warnings\n")
		for _, w := range result.Metadata.Warnings {
			sb.WriteString(fmt.Sprintf("    [!] %s\n", w))
		}
	}
	if len(result.Metadata.Errors) > 0 {
		sb.WriteString("\n[*] Errors\n")
		for _, e := range result.Metadata.Errors {
			sb.WriteString(fmt.Sprintf("    [x] %s\n", e))
		}
	}

	sb.WriteString("\n================================\n\n")

	return sb.String(), nil
}

// toXML serializes the complete scan result into a stable XML schema.
func (f *Formatter) toXML(result *models.ScanResult) (string, error) {
	doc := xmlScanReport{
		Target:         result.Target,
		JoomlaDetected: result.JoomlaDetected,
		DetectionSignals: xmlSignals{
			Items: append([]string(nil), result.DetectionSignals...),
		},
		Version: xmlVersion{
			Detected:   result.Version.Detected,
			Value:      result.Version.Version,
			Confidence: result.Version.Confidence,
			Methods:    xmlMethods{Items: append([]string(nil), result.Version.Methods...)},
		},
		Metadata: xmlMetadata{
			StartTime:          result.Metadata.StartTime,
			EndTime:            result.Metadata.EndTime,
			Duration:           result.Metadata.Duration,
			HTTPRequests:       result.Metadata.HTTPRequests,
			HTTPErrors:         result.Metadata.HTTPErrors,
			HTTPRetries:        result.Metadata.HTTPRetries,
			RateLimitedHits:    result.Metadata.RateLimitedHits,
			BreakerTripped:     result.Metadata.BreakerTripped,
			CredentialAttempts: result.Metadata.CredentialAttempts,
			CredentialErrors:   result.Metadata.CredentialErrors,
			CredentialsFound:   result.Metadata.CredentialsFound,
			CVESource:          result.Metadata.CVESource,
			Errors:             xmlMessages{Items: append([]string(nil), result.Metadata.Errors...)},
			Warnings:           xmlMessages{Items: append([]string(nil), result.Metadata.Warnings...)},
		},
	}

	for _, component := range result.Components {
		doc.Components.Items = append(doc.Components.Items, xmlComponent{
			Name: component.Name, Type: component.Type, Path: component.Path,
			Detected: component.Detected, Version: component.Version, Installed: component.Installed,
		})
	}
	for _, template := range result.Templates {
		doc.Templates.Items = append(doc.Templates.Items, xmlTemplate{
			Name: template.Name, Path: template.Path, Version: template.Version,
		})
	}
	for _, plugin := range result.Plugins {
		doc.Plugins.Items = append(doc.Plugins.Items, xmlPlugin{
			Name: plugin.Name, Path: plugin.Path, Version: plugin.Version,
			Author: plugin.Author, Installed: plugin.Installed,
		})
	}
	for _, user := range result.Users {
		doc.Users.Items = append(doc.Users.Items, xmlUser{
			Username: user.Username, ID: user.ID, Email: user.Email, Found: user.Found,
			Method: user.Method, PasswordValid: user.PasswordValid, Password: user.Password,
			PasswordAttempts: user.PasswordAttempts,
			PasswordErrors:   user.PasswordErrors,
		})
	}
	for _, vulnerability := range result.Vulnerabilities {
		doc.Vulnerabilities.Items = append(doc.Vulnerabilities.Items, xmlVulnerability{
			CVE: vulnerability.CVE, Title: vulnerability.Title,
			Description: vulnerability.Description, CVSS: vulnerability.CVSS,
			Severity: vulnerability.Severity, Affected: xmlValues{Items: append([]string(nil), vulnerability.Affected...)},
			PoC: vulnerability.PoC, Reference: vulnerability.Reference,
			References: xmlValues{Items: append([]string(nil), vulnerability.References...)},
			Source:     vulnerability.Source, Confidence: vulnerability.Confidence,
		})
	}

	data, err := xml.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encoding XML report: %w", err)
	}
	return xml.Header + string(data) + "\n", nil
}

type xmlScanReport struct {
	XMLName          xml.Name           `xml:"scan"`
	Target           string             `xml:"target"`
	JoomlaDetected   bool               `xml:"joomla_detected"`
	DetectionSignals xmlSignals         `xml:"detection_signals"`
	Version          xmlVersion         `xml:"version"`
	Components       xmlComponents      `xml:"components"`
	Templates        xmlTemplates       `xml:"templates"`
	Plugins          xmlPlugins         `xml:"plugins"`
	Users            xmlUsers           `xml:"users"`
	Vulnerabilities  xmlVulnerabilities `xml:"vulnerabilities"`
	Metadata         xmlMetadata        `xml:"metadata"`
}

type xmlSignals struct {
	Items []string `xml:"signal"`
}

type xmlMethods struct {
	Items []string `xml:"method"`
}

type xmlValues struct {
	Items []string `xml:"item"`
}

type xmlMessages struct {
	Items []string `xml:"message"`
}

type xmlVersion struct {
	Detected   bool       `xml:"detected"`
	Value      string     `xml:"value,omitempty"`
	Methods    xmlMethods `xml:"methods"`
	Confidence float64    `xml:"confidence"`
}

type xmlComponents struct {
	Items []xmlComponent `xml:"component"`
}

type xmlComponent struct {
	Name      string `xml:"name"`
	Type      string `xml:"type"`
	Path      string `xml:"path"`
	Detected  bool   `xml:"detected"`
	Version   string `xml:"version,omitempty"`
	Installed bool   `xml:"installed"`
}

type xmlTemplates struct {
	Items []xmlTemplate `xml:"template"`
}

type xmlTemplate struct {
	Name    string `xml:"name"`
	Path    string `xml:"path"`
	Version string `xml:"version,omitempty"`
}

type xmlPlugins struct {
	Items []xmlPlugin `xml:"plugin"`
}

type xmlPlugin struct {
	Name      string `xml:"name"`
	Path      string `xml:"path"`
	Version   string `xml:"version,omitempty"`
	Author    string `xml:"author,omitempty"`
	Installed bool   `xml:"installed"`
}

type xmlUsers struct {
	Items []xmlUser `xml:"user"`
}

type xmlUser struct {
	Username         string `xml:"username"`
	ID               int    `xml:"id,omitempty"`
	Email            string `xml:"email,omitempty"`
	Found            bool   `xml:"found"`
	Method           string `xml:"method,omitempty"`
	PasswordValid    bool   `xml:"password_valid"`
	Password         string `xml:"password,omitempty"`
	PasswordAttempts int    `xml:"password_attempts"`
	PasswordErrors   int    `xml:"password_errors"`
}

type xmlVulnerabilities struct {
	Items []xmlVulnerability `xml:"vulnerability"`
}

type xmlVulnerability struct {
	CVE         string    `xml:"cve"`
	Title       string    `xml:"title"`
	Description string    `xml:"description,omitempty"`
	CVSS        float64   `xml:"cvss"`
	Severity    string    `xml:"severity,omitempty"`
	Affected    xmlValues `xml:"affected"`
	PoC         string    `xml:"poc,omitempty"`
	Reference   string    `xml:"reference,omitempty"`
	References  xmlValues `xml:"references"`
	Source      string    `xml:"source,omitempty"`
	Confidence  string    `xml:"confidence,omitempty"`
}

type xmlMetadata struct {
	StartTime          string      `xml:"start_time"`
	EndTime            string      `xml:"end_time"`
	Duration           string      `xml:"duration"`
	HTTPRequests       int         `xml:"http_requests"`
	HTTPErrors         int         `xml:"http_errors"`
	HTTPRetries        int         `xml:"http_retries"`
	RateLimitedHits    int         `xml:"rate_limited_hits"`
	BreakerTripped     int         `xml:"circuit_breaker_tripped"`
	CredentialAttempts int         `xml:"credential_attempts"`
	CredentialErrors   int         `xml:"credential_errors"`
	CredentialsFound   int         `xml:"credentials_found"`
	CVESource          string      `xml:"cve_source,omitempty"`
	Errors             xmlMessages `xml:"errors"`
	Warnings           xmlMessages `xml:"warnings"`
}

// credentialCheckCounts defensively normalizes counters before presenting
// them. A malformed imported result must never display a negative number of
// conclusive checks.
func credentialCheckCounts(user models.User) (conclusive, inconclusive int) {
	inconclusive = user.PasswordErrors
	if inconclusive < 0 {
		inconclusive = 0
	}
	if inconclusive > user.PasswordAttempts {
		inconclusive = user.PasswordAttempts
	}
	conclusive = user.PasswordAttempts - inconclusive
	if conclusive < 0 {
		conclusive = 0
	}
	return conclusive, inconclusive
}

// GetFormatList returns list of supported formats
func GetFormatList() []string {
	return []string{"json", "markdown", "xml", "text"}
}
