package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/w41l3r/joomhound/internal/bruteforce"
	"github.com/w41l3r/joomhound/internal/cve"
	"github.com/w41l3r/joomhound/internal/enum"
	"github.com/w41l3r/joomhound/internal/http"
	"github.com/w41l3r/joomhound/internal/models"
)

// ScanConfig configures a scan.
type ScanConfig struct {
	Target          string
	Threads         int
	Timeout         time.Duration
	ProxyURL        string
	VerifySSL       bool
	UserAgent       string
	FollowRedirects bool

	// RateLimit is requests per second against the target. It was previously
	// hardcoded to 10 and ignored every user-supplied value.
	RateLimit float64

	// Enumeration options
	CheckVersion    bool
	CheckComponents bool
	CheckTemplates  bool
	CheckPlugins    bool
	CheckCVEs       bool

	// CveOnlineEnabled queries live CVE feeds (NVD + GitHub Advisory
	// Database) in addition to the offline database.
	CveOnlineEnabled bool
	// CveCacheDir overrides the CVE cache location. Empty = default.
	CveCacheDir string
	// CveCacheTTL overrides cache freshness. Zero = 24h.
	CveCacheTTL time.Duration
	// NVDAPIKey / GitHubToken raise the API rate limits when supplied.
	NVDAPIKey   string
	GitHubToken string

	// Brute-force options
	EnableBruteForce bool
	UserWordlist     []string
	PasswordWordlist []string
	UserMethod       string
	BruteDelay       time.Duration
	// SkipUserEnumeration goes straight to password testing against
	// KnownUsers, for when the operator already has valid usernames.
	SkipUserEnumeration bool
	KnownUsers          []string

	// Output options
	OutputFormat string
	Verbose      bool
}

// Scanner orchestrates a scan.
type Scanner struct {
	config    ScanConfig
	client    *http.Client
	detector  *enum.Detector
	cveDB     *cve.Database
	fetcher   cve.CVEFetcher
	startTime time.Time

	mu     sync.Mutex
	result *models.ScanResult
}

// NewScanner creates a scanner.
func NewScanner(config ScanConfig) (*Scanner, error) {
	if config.Target == "" {
		return nil, errors.New("target is required")
	}
	if config.Threads <= 0 {
		config.Threads = 10
	}
	if config.RateLimit <= 0 {
		config.RateLimit = http.DefaultRateLimit
	}

	clientConfig := http.ClientConfig{
		Timeout:         config.Timeout,
		ProxyURL:        config.ProxyURL,
		VerifySSL:       config.VerifySSL,
		UserAgent:       config.UserAgent,
		RateLimit:       config.RateLimit,
		MaxConnections:  config.Threads,
		FollowRedirects: config.FollowRedirects,
		MaxRetries:      http.DefaultMaxRetries,
		EnableCookies:   true,
		Breaker:         http.DefaultBreakerConfig(),
	}

	httpClient, err := http.NewClient(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP client: %w", err)
	}

	detector := enum.NewDetector(httpClient)
	detector.SetThreads(config.Threads)

	s := &Scanner{
		config:    config,
		client:    httpClient,
		detector:  detector,
		cveDB:     cve.NewDatabase(),
		startTime: time.Now(),
		result: &models.ScanResult{
			Target:          enum.NormalizeTarget(config.Target),
			Components:      []models.Component{},
			Templates:       []models.Template{},
			Users:           []models.User{},
			Vulnerabilities: []models.Vulnerability{},
			Metadata: models.ScanMetadata{
				Errors:   []string{},
				Warnings: []string{},
			},
		},
	}

	detector.OnMessage = func(msg string) { s.verbosef("%s", msg) }
	s.fetcher = s.buildCVEFetcher()

	return s, nil
}

// buildCVEFetcher assembles the CVE lookup pipeline: online providers with a
// disk cache and an offline fallback, or offline-only when --cve-online is not
// set.
func (s *Scanner) buildCVEFetcher() cve.CVEFetcher {
	offline := cve.NewOfflineFetcher(s.cveDB)

	if !s.config.CveOnlineEnabled {
		s.result.Metadata.CVESource = "offline"
		return offline
	}

	providers := []cve.CVEFetcher{
		cve.NewNVDProvider(cve.WithNVDAPIKey(firstNonEmpty(s.config.NVDAPIKey, os.Getenv("NVD_API_KEY")))),
		cve.NewGitHubProvider(cve.WithGitHubToken(firstNonEmpty(s.config.GitHubToken, os.Getenv("GITHUB_TOKEN")))),
	}

	opts := []cve.MultiFetcherOption{
		cve.WithFallback(offline),
		cve.WithTimeout(45 * time.Second),
		cve.WithErrorHandler(func(provider string, err error) {
			s.addWarning(fmt.Sprintf("CVE provider %s failed: %v", provider, err))
		}),
	}

	// A cache failure must not disable the feature.
	if cache, err := cve.NewDiskCache(s.config.CveCacheDir, s.config.CveCacheTTL); err == nil {
		opts = append(opts, cve.WithCache(cache))
		s.verbosef("[*] CVE cache: %s", cache.Dir())
	} else {
		s.addWarning(fmt.Sprintf("CVE disk cache unavailable, using memory cache: %v", err))
		opts = append(opts, cve.WithCache(cve.NewMemoryCache(s.config.CveCacheTTL)))
	}

	s.result.Metadata.CVESource = "online (nvd, github) with offline fallback"
	return cve.NewMultiFetcher(providers, opts...)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func (s *Scanner) verbosef(format string, args ...any) {
	if s.config.Verbose {
		fmt.Printf(format+"\n", args...)
	}
}

func (s *Scanner) addError(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.result.Metadata.Errors = append(s.result.Metadata.Errors, msg)
}

func (s *Scanner) addWarning(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.result.Metadata.Warnings = append(s.result.Metadata.Warnings, msg)
}

// Scan runs the full scan. ctx cancels every phase, so Ctrl-C now stops the
// scan instead of being ignored.
func (s *Scanner) Scan(ctx context.Context) *models.ScanResult {
	s.result.Metadata.StartTime = s.startTime.Format(time.RFC3339)
	target := s.result.Target

	s.verbosef("[*] Starting scan on %s", target)

	// Phase 1: fingerprint.
	detected, signals := s.detector.DetectJoomla(ctx, target)
	s.result.JoomlaDetected = detected
	s.result.DetectionSignals = signals

	if !detected {
		s.verbosef("[-] Joomla not detected")
		s.finalizeScan()
		return s.result
	}
	s.verbosef("[+] Joomla detected (%d signals: %v)", len(signals), signals)

	// Phase 2: enumeration, in parallel. Each goroutine writes to a local
	// variable and publishes under the mutex; the previous version had three
	// goroutines writing into the shared result struct concurrently.
	var wg sync.WaitGroup

	if s.config.CheckVersion {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.verbosef("[*] Detecting version...")
			info := s.detector.DetectVersion(ctx, target)

			s.mu.Lock()
			s.result.Version = *info
			s.mu.Unlock()

			if info.Detected {
				s.verbosef("[+] Version %s (confidence %.0f%%, via %v)",
					info.Version, info.Confidence*100, info.Methods)
			} else {
				s.verbosef("[-] Version not detected")
			}
		}()
	}

	if s.config.CheckComponents {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.verbosef("[*] Enumerating components...")
			comps := s.detector.EnumerateComponents(ctx, target)

			s.mu.Lock()
			s.result.Components = comps
			s.mu.Unlock()

			s.verbosef("[+] Found %d components", len(comps))
		}()
	}

	if s.config.CheckTemplates {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.verbosef("[*] Enumerating templates...")
			tpls := s.detector.EnumerateTemplates(ctx, target)

			s.mu.Lock()
			s.result.Templates = tpls
			s.mu.Unlock()

			s.verbosef("[+] Found %d templates", len(tpls))
		}()
	}

	wg.Wait()

	if ctx.Err() != nil {
		s.addError("scan cancelled: " + ctx.Err().Error())
		s.finalizeScan()
		return s.result
	}

	// Phase 3: CVE correlation.
	if s.config.CheckCVEs {
		s.verbosef("[*] Checking for CVEs (%s)...", s.result.Metadata.CVESource)
		s.checkCVEs(ctx)
	}

	// Phase 4/5: credential attacks.
	if s.config.EnableBruteForce {
		s.runBruteForce(ctx)
	}

	s.finalizeScan()
	return s.result
}

// checkCVEs correlates the detected version and components with CVE data.
func (s *Scanner) checkCVEs(ctx context.Context) {
	version := s.result.Version.Version

	var vulns []models.Vulnerability
	seen := make(map[string]bool)

	appendAdvisory := func(a cve.Advisory, affected []string, confidence string) {
		if seen[a.ID] {
			return
		}
		seen[a.ID] = true

		ref := ""
		if len(a.References) > 0 {
			ref = a.References[0]
		}

		vulns = append(vulns, models.Vulnerability{
			CVE:         a.ID,
			Title:       a.Title,
			Description: a.Description,
			CVSS:        a.CVSS,
			Severity:    a.SeverityLabel(),
			Affected:    affected,
			Reference:   ref,
			References:  a.References,
			Source:      a.Source,
			Confidence:  confidence,
		})
	}

	// Version-based correlation. Only meaningful with a precise version;
	// "3.x" is deliberately not matched against ranges.
	if s.result.Version.Detected && cve.IsVersionComplete(version) {
		advs, err := s.fetcher.Fetch(ctx, cve.Query{Product: "joomla", Version: version})
		if err != nil {
			s.addError(fmt.Sprintf("CVE lookup for version %s failed: %v", version, err))
		}
		for _, a := range advs {
			// The online feeds return a superset; filter to advisories whose
			// ranges actually cover the detected version.
			if a.AffectsVersion(version) {
				appendAdvisory(a, []string{"Joomla " + version}, "high (version range match)")
			}
		}
	} else if s.result.Version.Detected {
		s.addWarning(fmt.Sprintf(
			"version %q is too imprecise for CVE range matching; results limited to component correlation",
			version))
	}

	// Component-based correlation. Lower confidence: presence of a component
	// does not prove the vulnerable code path is reachable.
	for _, comp := range s.result.Components {
		if ctx.Err() != nil {
			break
		}
		advs, err := s.fetcher.Fetch(ctx, cve.Query{Product: "joomla", Component: comp.Name})
		if err != nil {
			s.addError(fmt.Sprintf("CVE lookup for component %s failed: %v", comp.Name, err))
			continue
		}
		for _, a := range advs {
			// If we know the version, do not report advisories it is not in.
			if cve.IsVersionComplete(version) && len(a.Ranges) > 0 && !a.AffectsVersion(version) {
				continue
			}
			appendAdvisory(a, []string{comp.Name}, "medium (component present)")
		}
	}

	s.mu.Lock()
	s.result.Vulnerabilities = vulns
	s.mu.Unlock()

	s.verbosef("[+] Found %d potential vulnerabilities", len(vulns))
}

// runBruteForce performs user enumeration and, if users are found, password
// attacks.
func (s *Scanner) runBruteForce(ctx context.Context) {
	if s.config.SkipUserEnumeration {
		users := make([]models.User, 0, len(s.config.KnownUsers))
		for _, u := range s.config.KnownUsers {
			users = append(users, models.User{Username: u, Found: true, Method: "operator-supplied"})
		}
		s.mu.Lock()
		s.result.Users = users
		s.mu.Unlock()
	} else if len(s.config.UserWordlist) > 0 {
		s.verbosef("[*] Enumerating users...")

		enumerator := bruteforce.NewUserEnumerator(s.client, s.config.Threads)
		enumerator.OnMessage = func(msg string) { s.verbosef("%s", msg) }

		users, err := enumerator.EnumerateUsers(ctx, s.result.Target, s.config.UserWordlist)
		if err != nil && ctx.Err() == nil {
			s.addError("user enumeration: " + err.Error())
		}

		s.mu.Lock()
		s.result.Users = users
		s.mu.Unlock()

		s.verbosef("[+] Enumerated %d users", len(users))
	}

	if len(s.config.PasswordWordlist) == 0 || len(s.result.Users) == 0 {
		return
	}

	s.verbosef("[*] Attempting password brute-force...")

	bf := bruteforce.NewPasswordBruteforcer(s.client, s.config.Threads)
	bf.DelayBetween = s.config.BruteDelay
	bf.OnMessage = func(msg string) { s.verbosef("%s", msg) }

	for i := range s.result.Users {
		if ctx.Err() != nil {
			return
		}

		user := s.result.Users[i]
		s.verbosef("[*] Brute-forcing passwords for user: %s", user.Username)

		res, err := bf.BruteForcePassword(ctx, s.result.Target, user.Username, s.config.PasswordWordlist)
		if res != nil {
			// Preserve enumeration metadata that the brute-forcer does not know.
			res.ID = user.ID
			res.Email = user.Email
			res.Method = user.Method

			s.mu.Lock()
			s.result.Users[i] = *res
			s.mu.Unlock()

			if res.PasswordValid {
				s.verbosef("[+] Valid credentials found: %s:%s", res.Username, res.Password)
			}
		}

		if errors.Is(err, bruteforce.ErrAccountLockout) {
			// Stop everything: continuing risks locking out real accounts.
			s.addError("brute-force aborted: " + err.Error())
			s.verbosef("[!] %v", err)
			return
		}
		if err != nil && ctx.Err() == nil {
			s.addError(fmt.Sprintf("brute-force for %s: %v", user.Username, err))
		}
	}
}

// finalizeScan records timings and the HTTP counters that were previously
// hardcoded to zero.
func (s *Scanner) finalizeScan() {
	endTime := time.Now()
	duration := endTime.Sub(s.startTime)

	stats := s.client.Stats()

	s.mu.Lock()
	s.result.Metadata.EndTime = endTime.Format(time.RFC3339)
	s.result.Metadata.Duration = duration.String()
	s.result.Metadata.HTTPRequests = int(stats.Requests)
	s.result.Metadata.HTTPErrors = int(stats.Errors)
	s.result.Metadata.HTTPRetries = int(stats.Retries)
	s.result.Metadata.RateLimitedHits = int(stats.RateLimited)
	s.result.Metadata.BreakerTripped = s.client.BreakerTripped()
	s.mu.Unlock()

	s.client.CloseIdleConnections()

	s.verbosef("\n[*] Scan completed in %s (%d requests, %d errors, %d retries)",
		duration.String(), stats.Requests, stats.Errors, stats.Retries)
}

// GetResult returns the scan result.
func (s *Scanner) GetResult() *models.ScanResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.result
}
