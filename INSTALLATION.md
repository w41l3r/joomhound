# JoomHound Installation and Usage

## Requirements

- Go 1.22 or newer
- Linux, macOS, or Windows
- Internet access only when downloading dependencies or using live CVE feeds

Target scanning itself does not require access to NVD or GitHub unless
`--cve-online` is enabled.

## Build from Source

```bash
git clone https://github.com/w41l3r/joomhound.git
cd joomhound
go mod download
go build -o joomhound ./cmd/joomhound
```

Verify the binary:

```bash
./joomhound version
./joomhound --help
```

To install it system-wide on Unix-like systems:

```bash
sudo install -m 0755 ./joomhound /usr/local/bin/joomhound
```

## Configuration

JoomHound looks for `$HOME/.joomhound/config.yaml`. You can select another file
with `--config`.

```bash
mkdir -p "$HOME/.joomhound"
cp .joomhound/config.example.yaml "$HOME/.joomhound/config.yaml"
```

A minimal configuration looks like this:

```yaml
timeout: 30
threads: 10
rate-limit: 5
proxy: ""
verify-ssl: true
no-redirects: false
format: text
cve-online: false
cve-cache-ttl: 24
brute-delay: 0
```

Configuration precedence is:

1. Command-line flags
2. Environment variables prefixed with `JOOMHOUND_`
3. Configuration file
4. Built-in defaults

Hyphens become underscores in environment variables. Examples:

```bash
export JOOMHOUND_TIMEOUT=60
export JOOMHOUND_RATE_LIMIT=2
export JOOMHOUND_VERIFY_SSL=true
```

Provider credentials also support their conventional environment variables:

```bash
export NVD_API_KEY='...'
export GITHUB_TOKEN='...'
```

Missing, malformed, and incorrectly typed files selected through `--config`
produce an error.

For safety, configuration files cannot select a target, enable `--brute`,
provide users or wordlists, select CVE query terms, choose an output path, or
purge the cache. Those operations must be explicit on the command line.

## Target URL Format

`enum`, `scan`, and `brute` require `-t/--target`. Supply an absolute HTTP or
HTTPS base URL:

```bash
joomhound enum --target https://target.example
joomhound enum --target https://target.example:8443/joomla
```

Do not pass the URL positionally. JoomHound reports an actionable error if you
do.

## Enumeration

The recommended first command is read-only enumeration:

```bash
joomhound enum -t https://target.example
```

Control individual phases when needed:

```bash
joomhound enum \
  -t https://target.example \
  --version-detect=true \
  --components=true \
  --templates=true \
  --cve=true
```

Add current NVD and GitHub Advisory data to the bundled database:

```bash
joomhound enum -t https://target.example --cve-online
```

## Full Scan

`scan` enables fingerprinting, version detection, component/template
enumeration, and CVE correlation:

```bash
joomhound scan -t https://target.example -o assessment.json
```

It does not test credentials unless `--brute` is explicitly supplied:

```bash
joomhound scan \
  -t https://target.example \
  --brute \
  --users users.txt \
  --passwords passwords.txt \
  --brute-delay 1000 \
  --threads 2 \
  --rate-limit 1 \
  -o assessment.json
```

## Credential Testing

Use `brute` only when credential attempts are explicitly authorized.

For a known username:

```bash
joomhound brute \
  -t https://target.example \
  --user admin \
  --passwords passwords.txt
```

To try read-only user discovery first:

```bash
joomhound brute \
  -t https://target.example \
  --users users.txt \
  --passwords passwords.txt
```

User discovery relies only on exact matches from an unauthenticated Joomla
public API. If that API is unavailable, discovery is skipped. Registration
forms are never submitted as a username oracle.

Password testing uses a new cookie session and CSRF token for each attempt.
Login POST requests are never retried. HTTP 429, lockout signatures, and WAF
indicators abort the run. Verbose output reports progress without printing
candidate passwords. Reports include per-user and aggregate candidate counts,
identify checks made inconclusive by request errors, and include isolated
login-session traffic in the HTTP totals.

## CVE Lookup

Query the bundled database without contacting a Joomla target:

```bash
joomhound cve --version 3.10.0
joomhound cve --component com_fields
```

Merge live providers with curated offline records:

```bash
joomhound cve --version 4.4.3 --online
```

Cache management:

```bash
joomhound cve --purge-cache
joomhound cve --purge-cache --cache-dir /path/to/joomhound-cache
```

Purge removes only JoomHound cache files matching its hashed filename format;
unrelated files in a custom directory are preserved.

## Network Controls

```bash
# Increase the per-request timeout
joomhound enum -t https://target.example --timeout 60

# Reduce concurrency and request rate
joomhound enum -t https://target.example --threads 3 --rate-limit 2

# Route traffic through an HTTP or SOCKS5 proxy
joomhound enum -t https://target.example --proxy http://127.0.0.1:8080
joomhound enum -t https://target.example --proxy socks5://127.0.0.1:1080

# Return redirect responses without following them
joomhound enum -t https://target.example --no-redirects

# Validate certificates on trusted HTTPS targets
joomhound enum -t https://target.example --verify-ssl
```

When enabled, redirects are restricted to the original hostname. Transient
retry behavior applies only to GET and HEAD requests.

## Output

Supported report formats are `text`, `json`, `xml`, and `markdown`.

```bash
joomhound enum -t https://target.example --format json -o report.json
joomhound enum -t https://target.example --format xml -o report.xml
joomhound enum -t https://target.example --format markdown -o report.md
```

An explicit `--format` or `--json` wins. Otherwise, a recognized output-file
extension selects the format before the environment/config default is
considered. `--json` is shorthand for `--format json`.

Without an output file, the report goes to stdout. Operational messages go to
stderr, allowing direct pipelines:

```bash
joomhound enum -t https://target.example --format json | jq '.'
joomhound scan -t https://target.example --format xml > report.xml
```

Files are written with permission mode `0600` because authorized credential
testing may place passwords in a report.

## Troubleshooting

### Target not detected

- Confirm that the URL includes `http://` or `https://`.
- Include the Joomla subdirectory, if present.
- Run with `--verbose`; progress remains on stderr.

```bash
joomhound enum -t https://target.example/joomla --verbose
```

### Timeout or connection resets

Reduce concurrency/rate and increase the per-request timeout:

```bash
joomhound enum -t https://target.example --threads 3 --rate-limit 2 --timeout 60
```

### Certificate validation failure

TLS verification is disabled by default for self-signed assessment targets.
If `--verify-ssl` is enabled, verify the target's trust chain or omit the flag
only when accepting that risk is within the engagement rules.

### Provider throttling

Set `NVD_API_KEY` and/or `GITHUB_TOKEN`, or run without `--cve-online` to use
the bundled database only.

## Legal Notice

Only use JoomHound against systems you own or have explicit written
authorization to test. Unauthorized access is illegal, and credential testing
can lock accounts or affect service availability even with safeguards enabled.
