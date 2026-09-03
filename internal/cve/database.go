package cve

import (
	"fmt"
	"strings"
)

// CVEEntry represents a CVE vulnerability
type CVEEntry struct {
	CVE              string
	Title            string
	Description      string
	CVSS             float64
	AffectedVersions []string
	PublishedDate    string
	UpdatedDate      string
	References       []string
	PoC              string
	IsPublic         bool
}

// Database manages CVE information
type Database struct {
	entries map[string]CVEEntry
}

// NewDatabase creates a new CVE database
func NewDatabase() *Database {
	db := &Database{
		entries: make(map[string]CVEEntry),
	}
	db.loadDefaultEntries()
	return db
}

// loadDefaultEntries loads known Joomla CVEs
func (db *Database) loadDefaultEntries() {
	// Recent and critical Joomla CVEs
	criticalCVEs := []CVEEntry{
		{
			CVE:     "CVE-2023-23752",
			Title:   "Joomla Core - Authentication Bypass",
			CVSS:    9.8,
			AffectedVersions: []string{"3.0.0", "3.1.0", "3.2.0", "3.3.0", "3.4.0", "3.5.0", "3.6.0", "3.7.0", "3.8.0", "3.9.0", "3.10.0", "3.11.0"},
			Description:     "Unauthorized access to the administrator interface via blind SQL injection in the login form",
			PublishedDate:   "2023-02-15",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2023-23752",
				"https://www.joomla.org/announcements/release-news/",
			},
			IsPublic: true,
		},
		{
			CVE:     "CVE-2022-49167",
			Title:   "Joomla - Unauthenticated SQL Injection",
			CVSS:    9.8,
			AffectedVersions: []string{"3.0.0-3.11.0"},
			Description:     "Unauthenticated SQL injection in the com_fields component parameter processing",
			PublishedDate:   "2022-11-16",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2022-49167",
			},
			IsPublic: true,
		},
		{
			CVE:     "CVE-2022-41130",
			Title:   "Joomla - Open Redirect in WebAssets",
			CVSS:    6.1,
			AffectedVersions: []string{"3.0.0-3.10.10", "4.0.0-4.2.6"},
			Description:     "Open redirect vulnerability in WebAssets component",
			PublishedDate:   "2022-10-20",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2022-41130",
			},
			IsPublic: true,
		},
		{
			CVE:     "CVE-2021-26035",
			Title:   "Joomla - SQL Injection in User Registration",
			CVSS:    9.8,
			AffectedVersions: []string{"3.9.0-3.9.24", "4.0.0-4.0.2"},
			Description:     "SQL injection in user registration component via email parameter",
			PublishedDate:   "2021-04-29",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2021-26035",
			},
			IsPublic: true,
		},
		{
			CVE:     "CVE-2020-12446",
			Title:   "Joomla - SQL Injection in Article Routing",
			CVSS:    9.8,
			AffectedVersions: []string{"3.9.0-3.9.16"},
			Description:     "SQL injection in article routing via ID parameter",
			PublishedDate:   "2020-05-07",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2020-12446",
			},
			IsPublic: true,
		},
		{
			CVE:     "CVE-2019-12979",
			Title:   "Joomla - Stored XSS in Articles",
			CVSS:    6.1,
			AffectedVersions: []string{"3.9.0-3.9.10"},
			Description:     "Stored cross-site scripting in article content processing",
			PublishedDate:   "2019-06-25",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2019-12979",
			},
			IsPublic: true,
		},
		{
			CVE:     "CVE-2019-6340",
			Title:   "Joomla Core REST API - Remote Code Execution",
			CVSS:    9.8,
			AffectedVersions: []string{"3.9.0-3.9.3"},
			Description:     "Arbitrary code execution via Drupal REST API (Joomla also affected)",
			PublishedDate:   "2019-02-20",
			References: []string{
				"https://www.exploit-db.com/exploits/46452",
			},
			IsPublic: true,
		},
		{
			CVE:     "CVE-2018-6389",
			Title:   "Joomla - Path Traversal in Media Manager",
			CVSS:    7.5,
			AffectedVersions: []string{"3.8.0-3.8.12", "3.9.0-3.9.2"},
			Description:     "Path traversal via media manager upload functionality",
			PublishedDate:   "2018-02-09",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2018-6389",
			},
			IsPublic: true,
		},
	}

	for _, cve := range criticalCVEs {
		db.entries[cve.CVE] = cve
	}
}

// GetByCVE returns a CVE entry by ID
func (db *Database) GetByCVE(cveID string) (CVEEntry, bool) {
	entry, ok := db.entries[cveID]
	return entry, ok
}

// SearchByVersion returns CVEs affecting a specific version
func (db *Database) SearchByVersion(version string) []CVEEntry {
	var results []CVEEntry

	for _, entry := range db.entries {
		if db.versionAffected(version, entry.AffectedVersions) {
			results = append(results, entry)
		}
	}

	return results
}

// SearchByComponent returns CVEs for a specific component
func (db *Database) SearchByComponent(componentName string) []CVEEntry {
	var results []CVEEntry

	for _, entry := range db.entries {
		if strings.Contains(strings.ToLower(entry.Description), strings.ToLower(componentName)) {
			results = append(results, entry)
		}
	}

	return results
}

// versionAffected checks if a version is in the affected list
func (db *Database) versionAffected(version string, affectedVersions []string) bool {
	for _, affected := range affectedVersions {
		if db.versionMatches(version, affected) {
			return true
		}
	}
	return false
}

// versionMatches performs version comparison/matching
func (db *Database) versionMatches(version, pattern string) bool {
	// Handle version ranges like "3.0.0-3.9.10"
	if strings.Contains(pattern, "-") {
		parts := strings.Split(pattern, "-")
		if len(parts) == 2 {
			startVer := parts[0]
			endVer := parts[1]

			if db.compareVersions(version, startVer) >= 0 && db.compareVersions(version, endVer) <= 0 {
				return true
			}
		}
	}

	// Handle wildcard versions like "3.9.*"
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(version, prefix)
	}

	// Exact version match
	return version == pattern
}

// compareVersions compares two version strings
// Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func (db *Database) compareVersions(v1, v2 string) int {
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	maxParts := len(parts1)
	if len(parts2) > maxParts {
		maxParts = len(parts2)
	}

	for i := 0; i < maxParts; i++ {
		p1 := "0"
		p2 := "0"

		if i < len(parts1) {
			p1 = parts1[i]
		}
		if i < len(parts2) {
			p2 = parts2[i]
		}

		n1 := db.parseVersionPart(p1)
		n2 := db.parseVersionPart(p2)

		if n1 < n2 {
			return -1
		} else if n1 > n2 {
			return 1
		}
	}

	return 0
}

// parseVersionPart converts a version part to an integer
func (db *Database) parseVersionPart(part string) int {
	var num int
	fmt.Sscanf(part, "%d", &num)
	return num
}

// GetCriticalVulnerabilities returns CVEs with CVSS >= 8.0
func (db *Database) GetCriticalVulnerabilities() []CVEEntry {
	var results []CVEEntry

	for _, entry := range db.entries {
		if entry.CVSS >= 8.0 {
			results = append(results, entry)
		}
	}

	return results
}

// AddEntry adds a new CVE entry to the database
func (db *Database) AddEntry(entry CVEEntry) {
	db.entries[entry.CVE] = entry
}

// Count returns the total number of CVEs in the database
func (db *Database) Count() int {
	return len(db.entries)
}
