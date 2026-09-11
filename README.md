# JoomHound

**Joomla reconnaissance and authorized credential-testing CLI**

JoomHound fingerprints Joomla installations, detects versions, enumerates known
components and templates, correlates CVEs, and can test explicitly authorized
administrator credentials. It is written in Go and designed to produce bounded,
repeatable scans rather than exploit a target.

---

## ✨ Features

- 🔍 **Multi-signal fingerprinting** - Manifests, generator tags, Joomla assets, JavaScript namespaces, cookies, and administrator endpoints
- 📦 **Component and template discovery** - Concurrent checks against a maintained built-in catalog
- 👤 **Low-impact user enumeration** - Exact matches from Joomla's public API; no registration submissions
- 🔐 **Session-aware password testing** - Cookies, CSRF tokens, and automatic lockout detection
- 🚨 **CVE correlation** - Curated offline entries plus optional NVD and GitHub Advisory data
- ⚡ **Bounded networking** - Connection pooling, response-size limits, rate limiting, and circuit breaking
- 🛡️ **Safer HTTP behavior** - Same-host redirects and retries limited to GET/HEAD requests
- 📊 **Report formats** - Complete JSON and XML reports, plus Markdown and text

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

## 📋 Target URLs

Commands that contact a Joomla site require `-t/--target`. Supply the absolute
base URL, including `http://` or `https://`. Non-default ports and subdirectory
installations are supported:

```bash
joomhound enum --target https://host.example:8443/joomla
```

The `cve` command is local/provider-based and does not accept a target URL.

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
joomhound cve --version 3.10.0

# Merge online feeds with the offline database
joomhound cve --version 3.10.0 --online

# Look up advisories for a component
joomhound cve --component com_fields
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
│   │   ├── users.go            # Public-API user enumeration
│   │   ├── passwords.go        # Session-aware password attacks
│   │   └── joomla.go           # Joomla-specific utilities
│   │
│   ├── cve/
│   │   ├── database.go         # Offline CVE database
│   │   ├── fetcher.go          # CVE source aggregation
│   │   ├── nvd.go              # NVD API provider
│   │   ├── github.go           # GitHub Advisory provider
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
--rate-limit float        Max requests/sec (default: 10; non-positive resets to 10)
-T, --threads int         Concurrent workers (default: 10)
--proxy string            HTTP/SOCKS5 proxy URL
--user-agent string       Custom User-Agent
--no-redirects            Do not follow HTTP redirects
--verify-ssl              Verify TLS certificates for HTTPS targets
-v, --verbose             Verbose output
-q, --quiet               Suppress banner
```

---

## ⚙️ Configuration

Copy [`.joomhound/config.example.yaml`](.joomhound/config.example.yaml) to
`$HOME/.joomhound/config.yaml`, or select a file with `--config`:

```yaml
timeout: 30
threads: 10
rate-limit: 5
verify-ssl: true
format: json
cve-online: false
```

Precedence is `CLI flags > JOOMHOUND_* environment variables > config file >
built-in defaults`. Hyphens become underscores in environment names; for
example, `rate-limit` maps to `JOOMHOUND_RATE_LIMIT`.

For safety, target URLs, credential-testing switches, usernames, wordlists,
output paths, CVE query terms, and cache purge remain CLI-only. A configuration
file cannot silently choose a target or enable brute-force.

An explicitly selected missing, malformed, or incorrectly typed config file is
reported as an error instead of being ignored.

---

## 📤 Output Streams

Without `-o/--output`, the selected report is written to stdout. Banner,
verbose progress, warnings, and file confirmations are written to stderr, so
structured output can be piped directly:

```bash
joomhound enum -t https://target.example --format json | jq '.version'
joomhound scan -t https://target.example --format xml > report.xml
```

Unknown formats and contradictory combinations such as `--json --format xml`
fail before any scan requests are sent.

An explicit `--format` or `--json` wins. Otherwise, a recognized output-file
extension selects the format before an environment/config default.

---

## 🚨 Safety Features

- ✅ **Account Lockout Detection** - Monitors HTTP 429, lockout messages, and WAF signatures
- ✅ **Rate Limiting** - Token bucket algorithm with configurable requests per second
- ✅ **Circuit Breaker** - Stops requests after repeated failures
- ✅ **Safe Retries** - Exponential backoff applies only to GET and HEAD requests
- ✅ **Redirect Boundaries** - Follows redirects only when the hostname remains unchanged
- ✅ **Read-Only User Enumeration** - Never submits registration forms to test usernames
- ✅ **Session Management** - Uses real cookies and CSRF tokens for login attempts
- ✅ **Connection Pooling** - Reuses connections to reduce target impact

---

## 📊 Performance

Runtime depends on target latency, enabled checks, rate limits, retries, and
wordlist sizes. JoomHound reports duration and HTTP request/error/retry counts
in every scan result so performance can be evaluated against the actual target.

---

## 📖 Documentation

- **[QUICKSTART.md](QUICKSTART.md)** - 5-minute getting started guide
- **[INSTALLATION.md](INSTALLATION.md)** - Detailed setup and configuration
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Design patterns and modules
- **[PROJECT_STATUS.md](PROJECT_STATUS.md)** - Implemented features and known limitations
- **[INDEX.md](INDEX.md)** - Documentation map and historical research labels

---

## 📄 License

JoomHound is released under the [MIT License](LICENSE).

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

- **Bugs and feature requests:** https://github.com/w41l3r/joomhound/issues
- A private vulnerability-disclosure channel must be published before the
  first community release; do not disclose security-sensitive details in a
  public issue.

---

**Created by:** [@w41l3r](https://github.com/w41l3r)  
**Version:** 1.0.0
