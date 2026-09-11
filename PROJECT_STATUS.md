# JoomHound Project Status

This file describes the current codebase rather than its original design
goals. See `joomhound --help` for the authoritative user interface.

## Current State

JoomHound is a functional Joomla reconnaissance and authorized
credential-testing CLI undergoing pre-release hardening. The binary currently
reports version `1.0.0`, and the project is distributed under the MIT License.

## Implemented and Tested

- Absolute target URL validation for `enum`, `scan`, and `brute`
- Multi-signal Joomla fingerprinting
- Precise and partial version detection with confidence/evidence
- Concurrent probing of 37 built-in core component names
- Template discovery from assets, listings, and ten known template names
- Scan-scoped response caching and soft-404 profiling
- Curated offline database containing ten verified CVE records
- Optional NVD and GitHub Advisory providers with range filtering,
  deduplication, caching, and graceful partial failure
- HTTP/SOCKS5 proxies, rate limiting, bounded bodies, connection pooling,
  cancellation, a circuit breaker, safe-method retries, and same-host redirects
- Read-only, exact-match user enumeration through Joomla's public API
- Administrator login testing with cookie isolation and CSRF token handling
- Immediate credential-test abort on HTTP 429 and lockout/WAF indicators
- Per-user and aggregate credential-attempt totals, with inconclusive request
  errors separated from rejected passwords and login-session traffic included
  in HTTP statistics
- Complete JSON and XML reports, plus text and Markdown summaries
- Machine-readable stdout separated from operational stderr
- YAML/environment configuration for passive defaults with CLI precedence
- Atomic report-file replacement with mode `0600`

The test suite includes unit and local HTTP integration coverage for the above
boundaries and is run with both normal and race-enabled Go tests.

## Intentionally Not Implemented

- Joomla exploitation or automatic payload execution
- Automatic registration-form submissions for username discovery
- Frontend or JSON API password attacks
- Plugin/module enumeration in the default scan
- Arbitrary third-party extension discovery beyond the built-in component list
- Proxy rotation, WAF bypass, spoofed-header presets, or evasion automation
- A hundreds-entry bundled CVE database

Some historical research documents discuss these ideas. They are not a list of
shipping features.

## Known Limitations

- The bundled component/template catalogs are small and primarily cover Joomla
  core and stock templates.
- Joomla's public users API is commonly protected; automatic username
  enumeration will then return no results. Use `--user` only for a username
  already known within the engagement.
- Text and Markdown are human-oriented summaries; JSON and XML are the complete
  machine-readable contracts.
- Version and component exposure are evidence of potential vulnerability, not
  proof that a vulnerable code path is exploitable.
- Live CVE completeness and latency depend on external providers and their rate
  limits.

## Release Readiness Work

Before a public release, the recommended remaining work is:

1. Add CI for `go test`, `go test -race`, `go vet`, and multi-platform builds.
2. Add reproducible fixtures for Joomla 3, 4, and 5 behavior.
3. Review the bundled CVE records on a scheduled cadence.
4. Produce checksummed release artifacts and a documented disclosure process.

## Validation Commands

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/joomhound
```
