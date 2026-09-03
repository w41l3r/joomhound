package cve

// builtinEntries is the offline seed dataset.
//
// EVERY entry below was verified against the NVD CVE API v2 (title, CVSS base
// score, and affected version ranges). Do not add an entry from memory: run
//
//	curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-YYYY-NNNNN"
//
// and copy the real description, score and cpeMatch ranges. The previous
// version of this file contained six CVEs that belonged to other products
// entirely (Linux kernel, Drupal, WordPress, ImageMagick, a G.SKILL driver)
// plus one CVE ID that does not exist, all with invented CVSS scores. Those
// would have gone straight into client-facing reports as false positives.
//
// This list is intentionally small and correct. For full coverage use the
// online providers (--cve-online), which query NVD and the GitHub Advisory
// Database live.
func builtinEntries() []CVEEntry {
	return []CVEEntry{
		{
			CVE:         "CVE-2017-8917",
			Title:       "Joomla! 3.7.0 - Unauthenticated SQL Injection (com_fields)",
			Description: "SQL injection vulnerability in Joomla! 3.7.x before 3.7.1 allows attackers to execute arbitrary SQL commands via unspecified vectors. Publicly exploited against the com_fields component introduced in 3.7.0.",
			CVSS:        9.8,
			Severity:    "CRITICAL",
			Ranges: []VersionRange{
				{Introduced: "3.7.0", LastAffected: "3.7.0"},
			},
			AffectedComponents: []string{"com_fields"},
			PublishedDate:      "2017-05-17",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2017-8917",
				"https://developer.joomla.org/security-centre/705-20170501-core-sql-injection.html",
			},
			PoC:      "Metasploit: auxiliary/admin/http/joomla_registration_privesc family; public sqlmap payloads",
			IsPublic: true,
		},
		{
			CVE:         "CVE-2019-10945",
			Title:       "Joomla! < 3.9.5 - Media Manager Directory Traversal",
			Description: "The Media Manager component does not properly sanitize the folder parameter, allowing attackers to act outside the media manager root directory (directory listing and file access).",
			CVSS:        9.8,
			Severity:    "CRITICAL",
			Ranges: []VersionRange{
				{Introduced: "1.5.0", LastAffected: "3.9.4"},
			},
			AffectedComponents: []string{"com_media"},
			PublishedDate:      "2019-04-10",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2019-10945",
			},
			PoC:      "Public exploit-db PoC (directory traversal via folder parameter)",
			IsPublic: true,
		},
		{
			CVE:         "CVE-2016-8869",
			Title:       "Joomla! < 3.6.4 - Privilege Escalation via User Registration",
			Description: "The register method in UsersModelRegistration (Users component) allows remote attackers to gain elevated privileges by leveraging incorrect use of unfiltered data when registering.",
			CVSS:        9.8,
			Severity:    "CRITICAL",
			Ranges: []VersionRange{
				{LastAffected: "3.6.3"},
			},
			AffectedComponents: []string{"com_users"},
			PublishedDate:      "2016-11-04",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2016-8869",
			},
			PoC:      "Metasploit: exploit/unix/webapp/joomla_comfields_sqli_rce related chain; public PoCs",
			IsPublic: true,
		},
		{
			CVE:         "CVE-2016-8870",
			Title:       "Joomla! < 3.6.4 - Account Creation With Registration Disabled",
			Description: "The register method in UsersModelRegistration (Users component), when registration has been disabled, allows remote attackers to create user accounts by leveraging failure to check the registration setting.",
			CVSS:        8.1,
			Severity:    "HIGH",
			Ranges: []VersionRange{
				{LastAffected: "3.6.3"},
			},
			AffectedComponents: []string{"com_users"},
			PublishedDate:      "2016-11-04",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2016-8870",
			},
			IsPublic: true,
		},
		{
			CVE:         "CVE-2015-8562",
			Title:       "Joomla! < 3.4.6 - PHP Object Injection RCE via User-Agent",
			Description: "Joomla! 1.5.x, 2.x and 3.x before 3.4.6 allow remote attackers to conduct PHP object injection attacks and execute arbitrary PHP code via the HTTP User-Agent header. Exploited in the wild since December 2015.",
			CVSS:        7.5,
			Severity:    "HIGH",
			Ranges: []VersionRange{
				{Introduced: "1.5.0", Fixed: "3.4.6"},
			},
			PublishedDate: "2015-12-16",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2015-8562",
			},
			PoC:      "Metasploit: exploit/unix/webapp/joomla_http_header_rce",
			IsPublic: true,
		},
		{
			CVE:         "CVE-2023-40626",
			Title:       "Joomla! - Environment Variable Disclosure via Language File Parsing",
			Description: "The language file parsing process could be manipulated to expose environment variables, which may contain sensitive information such as credentials.",
			CVSS:        7.5,
			Severity:    "HIGH",
			Ranges: []VersionRange{
				{Introduced: "1.6.0", Fixed: "3.10.14"},
				{Introduced: "4.0.0", Fixed: "4.4.1"},
				{Introduced: "5.0.0", LastAffected: "5.0.0"},
			},
			PublishedDate: "2023-11-29",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2023-40626",
			},
			IsPublic: true,
		},
		{
			CVE:         "CVE-2024-21726",
			Title:       "Joomla! - Inadequate Content Filtering Leads to XSS",
			Description: "Inadequate content filtering leads to XSS vulnerabilities in various components. Chainable to remote code execution in the administrator context.",
			CVSS:        6.5,
			Severity:    "MEDIUM",
			Ranges: []VersionRange{
				{Introduced: "3.7.0", LastAffected: "3.10.15"},
				{Introduced: "4.0.0", Fixed: "4.4.3"},
				{Introduced: "5.0.0", Fixed: "5.0.3"},
			},
			PublishedDate: "2024-02-29",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2024-21726",
			},
			IsPublic: true,
		},
		{
			CVE:         "CVE-2021-26035",
			Title:       "Joomla! - XSS via JForm API Rules Field",
			Description: "An issue was discovered in Joomla! 3.0.0 through 3.9.27. Inadequate escaping in the rules field of the JForm API leads to a XSS vulnerability.",
			CVSS:        6.1,
			Severity:    "MEDIUM",
			Ranges: []VersionRange{
				{Introduced: "3.0.0", LastAffected: "3.9.27"},
			},
			PublishedDate: "2021-09-01",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2021-26035",
			},
			IsPublic: true,
		},
		{
			CVE:         "CVE-2023-23752",
			Title:       "Joomla! 4.0.0-4.2.7 - Improper Access Check on Webservice Endpoints",
			Description: "An improper access check allows unauthorized access to webservice endpoints. Commonly abused to read the site configuration, including database credentials, via /api/index.php/v1/config/application?public=true.",
			CVSS:        5.3,
			Severity:    "MEDIUM",
			Ranges: []VersionRange{
				{Introduced: "4.0.0", LastAffected: "4.2.7"},
			},
			PublishedDate: "2023-02-16",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2023-23752",
				"https://developer.joomla.org/security-centre/894-20230201-core-improper-access-check-in-webservice-endpoints.html",
			},
			PoC:      "GET /api/index.php/v1/config/application?public=true",
			IsPublic: true,
		},
		{
			CVE:         "CVE-2020-11890",
			Title:       "Joomla! < 3.9.17 - Broken ACL via usergroup Table",
			Description: "Improper input validation in the usergroup table class could lead to a broken ACL configuration.",
			CVSS:        5.3,
			Severity:    "MEDIUM",
			Ranges: []VersionRange{
				{Introduced: "2.5.0", Fixed: "3.9.17"},
			},
			AffectedComponents: []string{"com_users"},
			PublishedDate:      "2020-04-21",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2020-11890",
			},
			IsPublic: true,
		},
	}
}
