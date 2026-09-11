# JoomHound Quick Start

JoomHound fingerprints and enumerates Joomla installations, correlates known
vulnerabilities, and optionally performs authorized credential testing.

Only run it against systems you own or have explicit written authorization to
test.

## Build

JoomHound requires Go 1.22 or newer.

```bash
git clone https://github.com/w41l3r/joomhound.git
cd joomhound
go build -o joomhound ./cmd/joomhound
./joomhound version
```

## Supply the Target

Commands that contact a site require `-t/--target`. Use the absolute base URL,
including the scheme. Ports and subdirectory installations are supported.

```bash
./joomhound enum --target https://target.example
./joomhound enum --target https://target.example:8443/joomla
```

A positional URL is not accepted. For example, use:

```bash
./joomhound enum --target https://target.example
```

not `./joomhound enum https://target.example`.

## Start with Read-Only Enumeration

`enum` does not test credentials. It fingerprints Joomla, detects its version,
enumerates known components and templates, and correlates the bundled CVE data.

```bash
./joomhound enum -t https://target.example
```

Useful variations:

```bash
# Verbose operational output goes to stderr
./joomhound enum -t https://target.example --verbose

# Disable individual enumeration phases
./joomhound enum -t https://target.example --components=false --templates=false

# Merge NVD and GitHub Advisory data with the offline database
./joomhound enum -t https://target.example --cve-online
```

## Generate Reports

Supported formats are `text`, `json`, `xml`, and `markdown`. An explicit
`--format` or `--json` wins; otherwise a recognized output-file extension
selects the format before the environment/config default is considered.

```bash
./joomhound enum -t https://target.example -o report.json
./joomhound enum -t https://target.example -o report.xml
./joomhound enum -t https://target.example --format markdown -o report.md
```

Without `--output`, the report goes to stdout. Banner, progress, and warnings
go to stderr, so structured reports remain safe to pipe:

```bash
./joomhound enum -t https://target.example --format json | jq '.version'
./joomhound enum -t https://target.example --format xml > report.xml
```

Reports written to disk use mode `0600` because credential-testing results may
contain passwords.

## Look Up CVEs Without Scanning

The `cve` command does not accept a target URL.

```bash
# Bundled database
./joomhound cve --version 3.10.0
./joomhound cve --component com_fields

# Bundled database plus live providers
./joomhound cve --version 4.4.3 --online
```

Use `NVD_API_KEY` and `GITHUB_TOKEN` to raise provider rate limits.

## Credential Testing Is Explicit

The `brute` command makes real administrator login attempts. Review the target,
username, wordlist, rate limit, concurrency, and engagement rules first.

```bash
./joomhound brute \
  --target https://target.example \
  --user admin \
  --passwords passwords.txt \
  --threads 2 \
  --rate-limit 1 \
  --brute-delay 1000
```

When `--user` is omitted, JoomHound can check a username wordlist against an
unauthenticated Joomla public API. It requires exact API matches and skips user
enumeration when that API is unavailable. It never submits registration forms
as an existence probe.

```bash
./joomhound brute \
  -t https://target.example \
  --users users.txt \
  --passwords passwords.txt
```

HTTP 429, lockout messages, and WAF indicators abort credential testing.

## Full Scan

`scan` runs enumeration and CVE correlation. Credential testing remains off
unless `--brute` is explicitly present.

```bash
# Passive workflow
./joomhound scan -t https://target.example -o assessment.json

# Explicitly include credential testing
./joomhound scan \
  -t https://target.example \
  --brute \
  --users users.txt \
  --passwords passwords.txt \
  --brute-delay 1000 \
  -o assessment.json
```

## Configuration

Copy the example file and edit passive defaults:

```bash
mkdir -p "$HOME/.joomhound"
cp .joomhound/config.example.yaml "$HOME/.joomhound/config.yaml"
```

Precedence is:

1. Command-line flags
2. `JOOMHOUND_*` environment variables
3. Configuration file
4. Built-in defaults

For example, `JOOMHOUND_RATE_LIMIT=2` overrides `rate-limit` in the file.
Targets, `--brute`, usernames, wordlists, output paths, CVE query terms, and
cache purge are intentionally CLI-only.

## Common Network Options

```bash
--timeout 60
--threads 5
--rate-limit 2
--proxy http://127.0.0.1:8080
--proxy socks5://127.0.0.1:1080
--no-redirects
--verify-ssl
```

TLS verification is disabled by default for self-signed assessment targets.
Use `--verify-ssl` when the target has a trusted certificate.

Run `./joomhound --help` or `./joomhound <command> --help` for the authoritative
command reference.
