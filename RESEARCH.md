# JoomHound Research & Architecture

## Competitive Analysis

### 1. **droopescan** (SamJoan)
**Strengths:**
- Language-agnostic scanning approach
- Modular architecture (CMS plugins)
- Good version detection via multiple fingerprints
- Extensible plugin system
- Support for multiple CMS (WordPress, Joomla, Drupal)

**Weaknesses:**
- Python-based (slower on large targets)
- Limited brute-force capabilities
- Outdated CVE database
- Weak user enumeration

**Key Techniques to Extract:**
- Fingerprinting methodology via hash comparison
- Component/template discovery via static file locations
- Version detection through multiple fallback methods
- Plugin loader architecture

---

### 2. **JoomlaScan** (drego85)
**Strengths:**
- Dedicated Joomla focus
- User enumeration via registration endpoint
- Password brute-force with rate limiting
- Better CVE integration
- Faster scanning than droopescan

**Weaknesses:**
- Written in Python (performance issues at scale)
- Limited component enumeration
- No template detection
- Proxy support is basic

**Key Techniques to Extract:**
- User enumeration via `/index.php?option=com_user&view=registration`
- Password attack patterns
- HTTP header analysis for Joomla detection
- Rate limiting strategies
- Concurrent connection pooling

---

### 3. **joomscan (OWASP)**
**Strengths:**
- Perl-based (mature codebase)
- Comprehensive component database
- Better template fingerprinting
- OWASP-aligned methodology
- Good documentation

**Weaknesses:**
- Perl dependency (not portable)
- Very slow execution
- Outdated (last commit 2017)
- No modern async capabilities
- Limited proxy support

**Key Techniques to Extract:**
- Component database structure
- Template fingerprinting approach
- OWASP vulnerability checklist
- Methodical scanning approach
- Detailed logging

---

## JoomHound Architecture (Go)

### Core Advantages of Go Implementation
1. **Single binary** - No runtime dependencies
2. **Concurrency** - Goroutines for multi-threading
3. **Performance** - Compiled to native code
4. **Portability** - Cross-platform compilation
5. **Memory efficiency** - Lightweight
6. **Modern async** - Built-in concurrency primitives

### Module Structure

```
internal/
├── http/              # HTTP client with proxy, rate limiting
├── enum/              # Version detection & component enumeration
│   ├── fingerprint/   # Version fingerprinting
│   ├── components/    # Component detection
│   ├── templates/     # Template detection
│   └── plugins/       # Plugin enumeration
├── bruteforce/        # User & password attacks
│   ├── users/         # User enumeration
│   ├── passwords/     # Password brute-force
│   └── strategies/    # Attack patterns
├── cve/               # CVE lookup and severity scoring
├── output/            # JSON, XML, Markdown export
└── models/            # Data structures
```

### Detection Methods Priority

1. **Version Detection** (combining techniques):
   - HTML comment parsing (`<!-- Joomla! X.X.X -->`)
   - Manifest file parsing
   - Administrator panel headers
   - Component versions
   - Administrator template files

2. **Component Detection**:
   - Known component paths
   - Component manifests
   - Admin URL patterns
   - HTTP response analysis

3. **Template Detection**:
   - CSS file fingerprinting
   - Template-specific files
   - Known template hashes

4. **User Enumeration**:
   - Registration endpoint analysis
   - JSON API endpoints
   - Error message analysis
   - User profile pages

5. **Password Brute-force**:
   - Authentication endpoints
   - Rate-limited concurrency
   - Token-aware attack
   - Smart wordlist selection

### Performance Targets
- Detect version: < 2 seconds
- Full component scan: < 10 seconds
- User enumeration (10 users): < 5 seconds
- Password brute-force (100 words): < 30 seconds (rate-limited)

### Configuration
- Smart rate limiting (backoff strategies)
- Proxy support (HTTP, SOCKS5)
- Custom headers
- User-Agent rotation
- SSL certificate verification toggle
- Timeout management
