package cve

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Query describes what to look up. Version may be empty, in which case
// providers fall back to a keyword search and range filtering is skipped.
type Query struct {
	// Product is the software name, e.g. "joomla".
	Product string
	// Version is the detected version, e.g. "4.2.7". Optional.
	Version string
	// Component narrows the search to a Joomla extension, e.g. "com_fields".
	Component string
}

// CacheKey is a stable identity for the query, used by the disk cache.
func (q Query) CacheKey() string {
	// Bump the schema prefix whenever provider/query semantics change. This
	// prevents older, broader results from surviving a correctness fix for a
	// full cache TTL.
	return strings.ToLower(strings.Join([]string{
		"v2",
		strings.TrimSpace(q.Product),
		strings.TrimSpace(q.Version),
		strings.TrimSpace(q.Component),
	}, "|"))
}

// VersionRange is an affected-version window reported by a provider.
type VersionRange struct {
	// Introduced is the first affected version (inclusive), if known.
	Introduced string `json:"introduced,omitempty"`
	// Fixed is the first *unaffected* version (exclusive upper bound).
	Fixed string `json:"fixed,omitempty"`
	// LastAffected is an inclusive upper bound, used when Fixed is unknown.
	LastAffected string `json:"last_affected,omitempty"`
	// Constraint is a raw expression such as ">= 4.0.0, < 4.2.8".
	Constraint string `json:"constraint,omitempty"`
}

// Contains reports whether version falls inside the range.
func (r VersionRange) Contains(version string) bool {
	if !IsVersionComplete(version) {
		return false
	}
	if r.Constraint != "" {
		return MatchConstraintRange(version, r.Constraint)
	}
	if r.Introduced != "" && CompareVersions(version, r.Introduced) < 0 {
		return false
	}
	if r.Fixed != "" && CompareVersions(version, r.Fixed) >= 0 {
		return false
	}
	if r.LastAffected != "" && CompareVersions(version, r.LastAffected) > 0 {
		return false
	}
	// A range with no bounds at all matches nothing (avoids false positives).
	return r.Introduced != "" || r.Fixed != "" || r.LastAffected != ""
}

// Advisory is a normalized vulnerability record from any provider.
type Advisory struct {
	ID          string         `json:"id"` // CVE ID, or GHSA when no CVE assigned
	Aliases     []string       `json:"aliases,omitempty"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	CVSS        float64        `json:"cvss"`
	CVSSVector  string         `json:"cvss_vector,omitempty"`
	Severity    string         `json:"severity,omitempty"`
	Published   time.Time      `json:"published,omitempty"`
	Modified    time.Time      `json:"modified,omitempty"`
	References  []string       `json:"references,omitempty"`
	Ranges      []VersionRange `json:"ranges,omitempty"`
	Source      string         `json:"source"` // provider name
}

// AffectsVersion reports whether the advisory covers the given version.
// When the advisory carries no usable range information it returns false:
// an unbounded advisory would otherwise match every target.
func (a Advisory) AffectsVersion(version string) bool {
	for _, r := range a.Ranges {
		if r.Contains(version) {
			return true
		}
	}
	return false
}

// SeverityLabel derives a severity string from the CVSS score when the
// provider did not supply one.
func (a Advisory) SeverityLabel() string {
	if a.Severity != "" {
		return strings.ToUpper(a.Severity)
	}
	switch {
	case a.CVSS >= 9.0:
		return "CRITICAL"
	case a.CVSS >= 7.0:
		return "HIGH"
	case a.CVSS >= 4.0:
		return "MEDIUM"
	case a.CVSS > 0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

// CVEFetcher is implemented by every CVE source (NVD, GitHub Advisory
// Database, the built-in offline database, ...).
type CVEFetcher interface {
	// Name identifies the provider in output and cache keys.
	Name() string
	// Fetch returns advisories matching q. It must honour ctx cancellation.
	Fetch(ctx context.Context, q Query) ([]Advisory, error)
}

// Cache is the storage contract used by MultiFetcher. See DiskCache.
type Cache interface {
	Get(key string) ([]Advisory, bool)
	Put(key string, advisories []Advisory) error
}

// MultiFetcher queries several providers, merges the curated offline source,
// caches complete results, and degrades gracefully when online sources fail.
type MultiFetcher struct {
	providers []CVEFetcher
	offline   CVEFetcher
	cache     Cache

	// Timeout bounds the whole multi-provider lookup.
	Timeout time.Duration

	// OnProviderError, when set, is called for each provider failure so the
	// caller can log it without MultiFetcher owning a logger.
	OnProviderError func(provider string, err error)
}

// MultiFetcherOption configures a MultiFetcher.
type MultiFetcherOption func(*MultiFetcher)

// WithCache attaches a cache.
func WithCache(c Cache) MultiFetcherOption {
	return func(m *MultiFetcher) { m.cache = c }
}

// WithOfflineSource adds a local source that is always merged with successful
// online results and remains available if every online provider fails.
func WithOfflineSource(f CVEFetcher) MultiFetcherOption {
	return func(m *MultiFetcher) { m.offline = f }
}

// WithFallback is retained for source compatibility. New code should use
// WithOfflineSource, whose name reflects that the source is always merged.
// Deprecated: use WithOfflineSource.
func WithFallback(f CVEFetcher) MultiFetcherOption {
	return WithOfflineSource(f)
}

// WithTimeout bounds the aggregate lookup.
func WithTimeout(d time.Duration) MultiFetcherOption {
	return func(m *MultiFetcher) { m.Timeout = d }
}

// WithErrorHandler registers a per-provider error callback.
func WithErrorHandler(fn func(provider string, err error)) MultiFetcherOption {
	return func(m *MultiFetcher) { m.OnProviderError = fn }
}

// NewMultiFetcher builds an aggregating fetcher.
func NewMultiFetcher(providers []CVEFetcher, opts ...MultiFetcherOption) *MultiFetcher {
	m := &MultiFetcher{
		providers: providers,
		Timeout:   30 * time.Second,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Name implements CVEFetcher.
func (m *MultiFetcher) Name() string {
	names := make([]string, 0, len(m.providers))
	for _, p := range m.providers {
		names = append(names, p.Name())
	}
	return "multi(" + strings.Join(names, ",") + ")"
}

// Fetch queries all providers concurrently and merges their results.
func (m *MultiFetcher) Fetch(ctx context.Context, q Query) ([]Advisory, error) {
	key := q.CacheKey()

	if m.cache != nil {
		if cached, ok := m.cache.Get(key); ok {
			return cached, nil
		}
	}

	if m.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, m.Timeout)
		defer cancel()
	}

	type result struct {
		provider string
		advs     []Advisory
		err      error
	}

	results := make(chan result, len(m.providers))
	var wg sync.WaitGroup

	for _, p := range m.providers {
		wg.Add(1)
		go func(p CVEFetcher) {
			defer wg.Done()
			// A panicking third-party parser must not kill the scan.
			defer func() {
				if r := recover(); r != nil {
					results <- result{provider: p.Name(), err: fmt.Errorf("panic: %v", r)}
				}
			}()
			advs, err := p.Fetch(ctx, q)
			results <- result{provider: p.Name(), advs: advs, err: err}
		}(p)
	}

	wg.Wait()
	close(results)

	var (
		merged    []Advisory
		errs      []error
		onlineOK  bool
		offlineOK bool
	)

	for r := range results {
		if r.err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r.provider, r.err))
			if m.OnProviderError != nil {
				m.OnProviderError(r.provider, r.err)
			}
			continue
		}
		onlineOK = true
		merged = append(merged, r.advs...)
	}

	// Curated entries complement live feeds: online providers do not expose a
	// reliable Joomla-component field and may lag project disclosures.
	if m.offline != nil {
		advs, err := m.offline.Fetch(context.WithoutCancel(ctx), q)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", m.offline.Name(), err))
			if m.OnProviderError != nil {
				m.OnProviderError(m.offline.Name(), err)
			}
		} else {
			offlineOK = true
			merged = append(merged, advs...)
		}
	}

	if !onlineOK && !offlineOK {
		if len(errs) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("all CVE providers failed: %w", errors.Join(errs...))
	}

	merged = DedupeAdvisories(merged)

	if m.cache != nil && len(errs) == 0 {
		// Cache only complete results. A partial-provider response should not
		// hide recovery of a failed source for the full cache TTL.
		_ = m.cache.Put(key, merged)
	}

	return merged, nil
}

// DedupeAdvisories merges advisories that describe the same vulnerability,
// preferring the record with the most information. Results are sorted by
// descending CVSS then by ID for stable output.
func DedupeAdvisories(in []Advisory) []Advisory {
	if len(in) == 0 {
		return nil
	}

	byID := make(map[string]Advisory, len(in))
	for _, a := range in {
		id := strings.ToUpper(strings.TrimSpace(a.ID))
		if id == "" {
			continue
		}
		a.ID = id

		existing, ok := byID[id]
		if !ok {
			byID[id] = a
			continue
		}
		byID[id] = mergeAdvisory(existing, a)
	}

	out := make([]Advisory, 0, len(byID))
	for _, a := range byID {
		out = append(out, a)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].CVSS != out[j].CVSS {
			return out[i].CVSS > out[j].CVSS
		}
		return out[i].ID < out[j].ID
	})

	return out
}

func mergeAdvisory(a, b Advisory) Advisory {
	if a.CVSS == 0 && b.CVSS > 0 {
		a.CVSS = b.CVSS
		a.CVSSVector = b.CVSSVector
		a.Severity = b.Severity
	}
	if a.Title == "" {
		a.Title = b.Title
	}
	if len(b.Description) > len(a.Description) {
		a.Description = b.Description
	}
	if a.Published.IsZero() {
		a.Published = b.Published
	}
	if b.Modified.After(a.Modified) {
		a.Modified = b.Modified
	}
	a.References = dedupeStrings(append(a.References, b.References...))
	a.Aliases = dedupeStrings(append(a.Aliases, b.Aliases...))
	a.Ranges = append(a.Ranges, b.Ranges...)
	if a.Source != b.Source && b.Source != "" {
		a.Source = a.Source + "+" + b.Source
	}
	return a
}

func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// OfflineFetcher adapts the built-in Database to the CVEFetcher interface so
// it can serve as the curated local provider inside a MultiFetcher.
type OfflineFetcher struct {
	DB *Database
}

// NewOfflineFetcher wraps db. A nil db creates a default database.
func NewOfflineFetcher(db *Database) *OfflineFetcher {
	if db == nil {
		db = NewDatabase()
	}
	return &OfflineFetcher{DB: db}
}

// Name implements CVEFetcher.
func (o *OfflineFetcher) Name() string { return "offline" }

// Fetch implements CVEFetcher against the embedded database.
func (o *OfflineFetcher) Fetch(_ context.Context, q Query) ([]Advisory, error) {
	var entries []CVEEntry
	if q.Component != "" {
		entries = o.DB.SearchByComponent(q.Component)
	} else if q.Version != "" {
		entries = o.DB.SearchByVersion(q.Version)
	} else {
		entries = o.DB.All()
	}

	out := make([]Advisory, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.ToAdvisory())
	}
	return out, nil
}
