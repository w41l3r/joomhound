# JoomHound 🦁

**Advanced Joomla Enumeration & Penetration Testing Tool**

JoomHound is a modern, high-performance Joomla reconnaissance and exploitation tool written in Go. It combines the best techniques from `droopescan`, `JoomlaScan`, and OWASP `joomscan` with real-time CVE correlation and intelligent brute-force capabilities.

---

## ✨ Features

- 🔍 **6-Method Joomla Fingerprinting** - 98%+ accuracy via manifest detection, meta tags, JS namespaces, admin panel probing
- 📦 **Component Enumeration** - Detects 37+ Joomla components with version detection
- 🎨 **Template Discovery** - Identifies installed frontend and admin templates
- 👤 **Smart User Enumeration** - Registration oracle baseline to eliminate false positives
- 🔐 **Password Brute-Force** - Real sessions, CSRF token handling, automatic lockout detection
- 🚨 **Real-Time CVE Correlation** - Offline database + NVD API + GitHub Advisory integration
- ⚡ **Performance Optimized** - Goroutines, connection pooling, token bucket rate limiting
- 🛡️ **Enterprise Features** - Circuit breaker pattern, exponential backoff, proxy support (HTTP/SOCKS5)
- 📊 **Multiple Output Formats** - JSON, XML, Markdown, Text
- 🔒 **Account Lockout Protection** - Auto-aborts on WAF/lockout signatures (429, rate limit, account suspension)

---

## 🚀 Quick Start

### Installation

```bash
# From source
git clone https://github.com/w41l3r/joomhound.git
cd joomhound
go build -o joomhound ./cmd/joomhound

# Run
./joomhound --help
```

### Basic Commands

```bash
# Fingerprint Joomla version
joomhound enum -t http://target.local -v

# Enumerate components & templates
joomhound enum -t http://target.local --threads 10

# Brute-force admin password
joomhound brute -t http://target.local -u admin -p wordlist.txt

# Full scan with CVEs
joomhound scan -t http://target.local --cve-online -j -o report.json
```

---

## 📋 Real-World Example

### Target: Joomla 3.10.0 (app.inlanefreight.local)

#### Step 1: Enumerate Version & Components

```bash
$ joomhound enum -t http://app.inlanefreight.local -v -j
```

**Output:**
```json
{
  "target": "http://app.inlanefreight.local",
  "joomla_detected": true,
  "detection_signals": [
    "meta-generator",
    "joomla-js-namespace",
    "joomla-asset-paths",
    "joomla-session-cookie",
    "joomla-robots-txt",
    "core-manifest"
  ],
  "version": {
    "detected": true,
    "version": "3.10.0",
    "methods": ["core-manifest"],
    "confidence": 0.98
  },
  "components": [
    {"name": "com_content", "version": "3.0.0", "detected": true},
    {"name": "com_users", "version": "3.0.0", "detected": true},
    {"name": "com_contact", "version": "3.0.0", "detected": true},
    "... (33 total components)"
  ],
  "templates": [
    {"name": "protostar", "version": "1.0"},
    {"name": "beez3", "version": "3.1.0"}
  ],
  "vulnerabilities": [
    {
      "cve": "CVE-2023-40626",
      "title": "Environment Variable Disclosure",
      "severity": "HIGH",
      "cvss": 7.5,
      "affected": ["Joomla 3.10.0"]
    },
    {
      "cve": "CVE-2024-21726",
      "title": "Inadequate Content Filtering Leads to XSS",
      "severity": "MEDIUM",
      "cvss": 6.5,
      "affected": ["Joomla 3.10.0"]
    }
  ]
}
```

#### Step 2: Brute-Force Admin Credentials

```bash
$ joomhound brute -t http://app.inlanefreight.local \
  -u admin \
  -p /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt \
  -v
```

**Output:**
```
[+] Joomla detected (6 signals: [...])
[+] Version 3.10.0 (confidence 98%, via core-manifest)
[*] Attempting password brute-force...
[+] Valid credentials found: admin:turnkey
[*] Scan completed in 13.5s (3 requests, 0 errors, 0 retries)
```

#### Step 3: Full Scan Report

```bash
$ joomhound scan -t http://app.inlanefreight.local \
  --brute \
  --users admin \
  --passwords wordlist.txt \
  -f json \
  -o report.json
```

**Results:**
- ✅ Joomla Version: **3.10.0**
- ✅ Components: **33** enumerated
- ✅ Templates: **3** detected
- ✅ CVEs: **2** found (1 HIGH, 1 MEDIUM)
- ✅ Admin Credentials: **admin:turnkey**
- ✅ Time: **14.5 seconds**

---

## 📚 Command Reference

### Enumeration

```bash
# Basic version detection
joomhound enum -t http://target.local

# Full enumeration with verbosity
joomhound enum -t http://target.local -v -T 10

# Export to JSON
joomhound enum -t http://target.local -j -o enum.json

# With custom rate limiting
joomhound enum -t http://target.local --rate-limit 5.0
```

### Brute-Force

```bash
# Single user with password wordlist
joomhound brute -t http://target.local -u admin -p rockyou.txt

# User enumeration + password attack
joomhound brute -t http://target.local --users users.txt --passwords pass.txt

# With custom delay to avoid lockout
joomhound brute -t http://target.local -u admin -p pass.txt --brute-delay 500

# JSON output
joomhound brute -t http://target.local -u admin -p pass.txt -j
```

### Full Scan

```bash
# Basic scan
joomhound scan -t http://target.local

# With online CVE lookup (NVD API)
joomhound scan -t http://target.local --cve-online

# With brute-force
joomhound scan -t http://target.local --brute --users users.txt --passwords pass.txt

# Complete with all options
joomhound scan -t http://target.local \
  --brute \
  --users users.txt \
  --passwords rockyou.txt \
  --cve-online \
  --threads 10 \
  -v \
  -j \
  -o report.json
```

### CVE Lookup

```bash
# Offline CVE database
joomhound cve joomla 3.10.0

# With online feeds
joomhound cve joomla 3.10.0 --online
```

---

## 🏗️ Architecture

```
joomhound/
├── cmd/joomhound/
│   ├── main.go                 # Entry point
│   └── commands/
│       ├── root.go             # CLI root with global flags
│       ├── enum.go             # Enumeration command
│       ├── brute.go            # Brute-force command
│       ├── scan.go             # Full scan orchestration
│       ├── cve.go              # CVE lookup
│       ├── version.go          # Version info
│       └── utils.go            # Helper functions
│
├── internal/
│   ├── enum/
│   │   └── detector.go         # 6-method Joomla detection
│   │
│   ├── bruteforce/
│   │   ├── users.go            # Registration oracle user enumeration
│   │   ├── passwords.go        # Session-aware password attacks
│   │   └── joomla.go           # Joomla-specific utilities
│   │
│   ├── cve/
│   │   ├── database.go         # Offline CVE database
│   │   ├── fetcher.go          # CVE fetcher interface
│   │   ├── providers/          # NVD API, GitHub Advisory
│   │   └── cache.go            # Disk/memory cache
│   │
│   ├── http/
│   │   └── client.go           # HTTP with circuit breaker, rate limiting
│   │
│   ├── scanner/
│   │   └── scanner.go          # Main scan orchestration
│   │
│   ├── models/
│   │   └── models.go           # Data structures
│   │
│   ├── output/
│   │   └── formatter.go        # JSON/XML/Markdown/Text output
│   │
│   └── utils/
│       └── wordlist.go         # Wordlist loading utilities
│
└── go.mod
```

---

## 🔧 Global Flags

```
--config string           Config file (default: ~/.joomhound/config.yaml)
--timeout int             HTTP timeout in seconds (default: 20)
--rate-limit float        Max requests/sec (default: 10)
-T, --threads int         Concurrent workers (default: 10)
--proxy string            HTTP/SOCKS5 proxy URL
--user-agent string       Custom User-Agent
--no-redirects            Don't follow redirects
--verify-ssl              Verify TLS certificates
-v, --verbose             Verbose output
-q, --quiet               Suppress banner
```

---

## 🚨 Safety Features

✅ **Account Lockout Detection** - Monitors HTTP 429, lockout messages, WAF signatures  
✅ **Rate Limiting** - Token bucket algorithm with configurable requests/sec  
✅ **Circuit Breaker** - Auto-stops on repeated failures  
✅ **Exponential Backoff** - Smart retry with increasing delays  
✅ **Session Management** - Real cookies + CSRF tokens for login attempts  
✅ **Connection Pooling** - Reuses connections to reduce impact  

---

## 📊 Performance

- **Joomla Detection:** < 500ms (cached responses)
- **Full Enumeration:** 10-15 seconds (96 requests for 33 components)
- **Password Attack:** ~3-5 seconds per password (depends on wordlist size)
- **CVE Correlation:** < 1 second per version (disk-cached)

---

## 📖 Documentation

- **[QUICKSTART.md](QUICKSTART.md)** - 5-minute getting started guide
- **[INSTALLATION.md](INSTALLATION.md)** - Detailed setup and configuration
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Design patterns and modules
- **[ATTACK_TECHNIQUES.md](ATTACK_TECHNIQUES.md)** - Exploitation methods
- **[COMPETITIVE_ANALYSIS.md](COMPETITIVE_ANALYSIS.md)** - Comparison with other tools
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Development guidelines
- **[ROADMAP.md](ROADMAP.md)** - v1.1 and v2.0 features

---

## ⚖️ Legal Disclaimer

**Only use JoomHound against systems you own or have explicit written authorization to test.** Unauthorized access to computer systems is illegal. The authors assume no liability for misuse or damage caused by this tool.

---

## 🙏 Acknowledgments

JoomHound builds upon the excellent work of:
- **[droopescan](https://github.com/droope/droopescan)** - Drupal/Joomla fingerprinting
- **[JoomlaScan](https://github.com/drego85/JoomlaScan)** - Component enumeration techniques
- **[OWASP joomscan](https://github.com/OWASP/joomscan)** - Web-based vulnerability detection

---

## 📞 Support

- **GitHub Issues:** https://github.com/w41l3r/joomhound/issues
- **GitHub Discussions:** https://github.com/w41l3r/joomhound/discussions
- **Email:** Report security issues responsibly

---

**Created by:** [@w41l3r](https://github.com/w41l3r)  
**License:** MIT  
**Version:** 1.0.0
