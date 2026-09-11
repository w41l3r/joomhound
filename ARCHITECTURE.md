# JoomHound Architecture

This document describes the current implementation. Planned features belong in
the roadmap and are not presented here as available functionality.

## Execution Flow

```text
Cobra command
    |
    +-- configuration loader
    |     CLI > JOOMHOUND_* environment > YAML > defaults
    |
    +-- scanner orchestrator
          |
          +-- bounded HTTP client
          +-- Joomla detector/enumerator
          +-- CVE correlation
          +-- optional credential testing
          |
          +-- ScanResult
                 |
                 +-- text / JSON / XML / Markdown formatter
```

The `enum` and `scan` commands use the scanner. The `brute` command uses the
same scanner and explicitly enables its credential-testing phase. The `cve`
command queries vulnerability sources without contacting a Joomla target.

## CLI and Configuration

Code: `cmd/joomhound/commands/`

Cobra defines the command tree and flags. A pre-run configuration loader reads
an explicit `--config` file or `$HOME/.joomhound/config.yaml`. Only passive
defaults are configurable. Target selection, credential wordlists, `--brute`,
CVE query terms, output paths, and cache purge stay CLI-only.

Configuration precedence is:

1. Explicit command-line flag
2. `JOOMHOUND_*` environment variable
3. YAML configuration value
4. Flag default

Malformed files and invalid value types are returned to the caller instead of
being silently ignored.

## Scanner

Code: `internal/scanner/scanner.go`

`Scanner` owns a scan-scoped HTTP client, detector, CVE source, and result. Its
workflow is:

1. Normalize and fingerprint the target.
2. If Joomla is detected, run version, component, and template checks in
   parallel when enabled.
3. Correlate precise versions and detected components with CVE records.
4. Run user/password testing only when the command explicitly enables it.
5. Record timing and HTTP counters and close idle connections.

Concurrent phases publish results under a mutex. Operational messages use a
dedicated, concurrency-safe logger supplied through `ScanConfig.LogWriter`.
The CLI directs this logger to stderr.

## HTTP Client

Code: `internal/http/`

The scan-scoped client provides:

- Context-aware timeouts and cancellation
- Token-bucket rate limiting shared by workers and login sessions
- Bounded response bodies
- Connection pooling sized for scan concurrency
- HTTP, HTTPS, and SOCKS5 proxy support
- Optional TLS certificate validation
- A circuit breaker for repeated target failures
- Exponential backoff for GET and HEAD only
- A ten-hop redirect limit restricted to the original hostname
- Isolated cookie jars for Joomla login attempts

POST requests are never automatically retried. A redirect policy refusal is
also non-retryable.

HTTP counters are collected atomically. The primary scan client's counters are
included in `ScanMetadata`.

## Joomla Detection and Enumeration

Code: `internal/enum/detector.go`

Detection combines several independent signals, including:

- Joomla generator metadata
- Joomla JavaScript and asset paths
- Joomla-style session cookies
- `robots.txt` patterns
- Core manifest files
- Administrator endpoints

Responses are cached for the duration of the scan so different detection
methods do not repeatedly fetch the same URL.

Version detection checks exposed manifests, language files, changelogs,
generator metadata, HTML comments, and major-version assets. Precise versions
and partial branches such as `3.x` are distinguished because partial versions
cannot safely match CVE ranges.

Component enumeration probes a built-in list of 37 core component names on
site and administrator paths. Template discovery combines page asset
references, exposed directory listings, and a small stock-template list.
Random nonexistent paths establish a soft-404 baseline before path results are
accepted. Component versions are recorded only when a readable extension
manifest exposes one.

Plugin enumeration is not currently executed, although a plugin model remains
in the result schema for future compatibility.

## CVE Correlation

Code: `internal/cve/`

The bundled database contains a deliberately small curated set of ten entries.
It prioritizes verified IDs, scores, references, affected ranges, and explicit
component mappings over broad but unverified coverage.

With `--cve-online`, `MultiFetcher` queries:

- NVD API v2
- GitHub Advisory Database for the `joomla/joomla-cms` Composer package
- The bundled offline database

The offline source is always merged with successful online results. Records
are normalized and deduplicated by CVE/GHSA identifier. Partial provider
results are returned but not cached, allowing a failed provider to recover on
the next run.

Version lookups use provider-supported version filters and then verify parsed
ranges locally. Component lookups use NVD component keywords plus exact
curated mappings. GitHub core-package results are skipped for component-only
queries because that API cannot express Joomla extension scope reliably.

Disk cache filenames are SHA-256 query hashes. Purge deletes only files that
match that cache-owned naming convention.

## User Enumeration and Credential Testing

Code: `internal/bruteforce/`

Automatic user enumeration is read-only. It first checks whether Joomla's
unauthenticated users API is available and then requires an exact username
match from its response. If the API is unavailable, enumeration is skipped.
JoomHound does not submit registration forms as an existence oracle.

For a known user, `--user` bypasses enumeration and records the username as
operator-supplied.

Each password attempt:

1. Creates an isolated cookie session.
2. Fetches the administrator login page.
3. Extracts Joomla's CSRF token when present.
4. Sends one login POST.
5. Fetches the administrator page again to verify an authenticated structural
   marker rather than relying on generic words.

Login sessions have no retry budget. HTTP 429, known lockout text, CAPTCHA/WAF
signals, and excessive consecutive failures stop the attack. Password jobs are
fed through a bounded worker pool and cancellation stops producers/workers.

The numeric contact/profile enumeration helper exists as an internal bounded
API but is not exposed by a CLI flag or used by the default workflow.

## Result and Output Contracts

Code: `internal/models/models.go`, `internal/output/formatter.go`

`ScanResult` is the canonical result and includes detection evidence, version,
components, templates, plugins, users, vulnerabilities, and scan metadata.

JSON and XML serialize the complete result. Markdown and text provide
human-oriented summaries. Unknown formats are rejected. The CLI keeps machine
reports on stdout and sends banner, progress, warnings, and file confirmations
to stderr. Disk reports use mode `0600` because they may contain credentials.

## Tests

Tests cover the major regression boundaries:

- Target/help/config parsing
- stdout/stderr separation and output validation
- Complete, well-formed XML
- Rate limiting, cancellation, retries, redirects, body limits, and breaker
- CSRF-aware login, false-positive prevention, and lockout handling
- Read-only exact-match user enumeration
- Version constraints, CVE providers, merging, cache behavior, and purge safety
- End-to-end scanner behavior using local HTTP fixtures

Run:

```bash
go test ./...
go test -race ./...
go vet ./...
```
