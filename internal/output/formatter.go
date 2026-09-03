package output

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/w41l3r/joomhound/internal/models"
)

type Formatter struct {
	format string // json, xml, markdown, text
}

func NewFormatter(format string) *Formatter {
	if format == "" {
		format = "text"
	}
	return &Formatter{
		format: strings.ToLower(format),
	}
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
	default:
		return f.toText(result)
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

	// Users Found
	sb.WriteString("### Users Enumerated\n\n")
	if len(result.Users) > 0 {
		sb.WriteString("| Username | Email | Status |\n")
		sb.WriteString("|----------|-------|--------|\n")
		for _, user := range result.Users {
			status := "❌"
			if user.Found {
				status = "✅"
			}
			sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n",
				user.Username, user.Email, status))
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("No users enumerated.\n\n")
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

	// Users
	sb.WriteString("\n[*] Users Enumerated\n")
	if len(result.Users) > 0 {
		for _, user := range result.Users {
			if user.Found {
				sb.WriteString(fmt.Sprintf("    [+] %s\n", user.Username))
				if user.Email != "" {
					sb.WriteString(fmt.Sprintf("        Email: %s\n", user.Email))
				}
				if user.PasswordValid {
					sb.WriteString(fmt.Sprintf("        Password: %s\n", user.Password))
				}
			}
		}
	} else {
		sb.WriteString("    [-] No users enumerated\n")
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

// toXML converts result to XML format (basic implementation)
func (f *Formatter) toXML(result *models.ScanResult) (string, error) {
	var sb strings.Builder

	sb.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	sb.WriteString("<scan>\n")
	sb.WriteString(fmt.Sprintf("  <target>%s</target>\n", escapeXML(result.Target)))
	sb.WriteString(fmt.Sprintf("  <timestamp>%s</timestamp>\n", result.Metadata.StartTime))

	sb.WriteString("  <detection>\n")
	if result.JoomlaDetected {
		sb.WriteString("    <joomla>true</joomla>\n")
		if result.Version.Detected {
			sb.WriteString(fmt.Sprintf("    <version>%s</version>\n", result.Version.Version))
		}
	} else {
		sb.WriteString("    <joomla>false</joomla>\n")
	}
	sb.WriteString("  </detection>\n")

	if len(result.Components) > 0 {
		sb.WriteString("  <components>\n")
		for _, comp := range result.Components {
			if comp.Detected {
				sb.WriteString("    <component>\n")
				sb.WriteString(fmt.Sprintf("      <name>%s</name>\n", escapeXML(comp.Name)))
				sb.WriteString(fmt.Sprintf("      <type>%s</type>\n", comp.Type))
				sb.WriteString(fmt.Sprintf("      <path>%s</path>\n", comp.Path))
				sb.WriteString("    </component>\n")
			}
		}
		sb.WriteString("  </components>\n")
	}

	sb.WriteString("</scan>\n")

	return sb.String(), nil
}

// escapeXML escapes special XML characters
func escapeXML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}

// GetFormatList returns list of supported formats
func GetFormatList() []string {
	return []string{"json", "markdown", "xml", "text"}
}
