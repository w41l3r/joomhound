package cve

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// stubFetcher is a controllable CVEFetcher for testing MultiFetcher.
type stubFetcher struct {
	name  string
	advs  []Advisory
	err   error
	calls int
}

func (s *stubFetcher) Name() string { return s.name }
func (s *stubFetcher) Fetch(ctx context.Context, q Query) ([]Advisory, error) {
	s.calls++
	return s.advs, s.err
}

func TestMultiFetcherMergesProviders(t *testing.T) {
	a := &stubFetcher{name: "a", advs: []Advisory{{ID: "CVE-2023-1", CVSS: 5.0, Source: "a"}}}
	b := &stubFetcher{name: "b", advs: []Advisory{{ID: "CVE-2023-2", CVSS: 9.8, Source: "b"}}}

	m := NewMultiFetcher([]CVEFetcher{a, b})

	got, err := m.Fetch(context.Background(), Query{Product: "joomla", Version: "3.9.4"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d advisories, want 2", len(got))
	}
	// Results are sorted by descending CVSS.
	if got[0].ID != "CVE-2023-2" {
		t.Fatalf("first advisory = %s, want CVE-2023-2 (highest CVSS)", got[0].ID)
	}
}

// TestMultiFetcherFallsBackOffline is the core resilience requirement: if NVD
// and GitHub are unreachable, --cve-online must degrade to the offline
// database rather than returning nothing.
func TestMultiFetcherFallsBackOffline(t *testing.T) {
	failing1 := &stubFetcher{name: "nvd", err: errors.New("connection refused")}
	failing2 := &stubFetcher{name: "github", err: errors.New("dns failure")}
	fallback := &stubFetcher{name: "offline", advs: []Advisory{{ID: "CVE-2017-8917", CVSS: 9.8}}}

	m := NewMultiFetcher([]CVEFetcher{failing1, failing2}, WithFallback(fallback))

	got, err := m.Fetch(context.Background(), Query{Product: "joomla", Version: "3.7.0"})
	if err != nil {
		t.Fatalf("Fetch should have fallen back, got error: %v", err)
	}
	if len(got) != 1 || got[0].ID != "CVE-2017-8917" {
		t.Fatalf("got %+v, want the offline advisory", got)
	}
	if fallback.calls != 1 {
		t.Fatalf("fallback called %d times, want 1", fallback.calls)
	}
}

func TestMultiFetcherPartialFailureStillReturns(t *testing.T) {
	ok := &stubFetcher{name: "github", advs: []Advisory{{ID: "CVE-2024-21726", CVSS: 6.5}}}
	bad := &stubFetcher{name: "nvd", err: errors.New("503")}

	var reported string
	m := NewMultiFetcher([]CVEFetcher{ok, bad},
		WithErrorHandler(func(p string, err error) { reported = p }))

	got, err := m.Fetch(context.Background(), Query{Product: "joomla"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d advisories, want 1", len(got))
	}
	if reported != "nvd" {
		t.Fatalf("error handler saw %q, want %q", reported, "nvd")
	}
}

func TestMultiFetcherUsesCache(t *testing.T) {
	p := &stubFetcher{name: "nvd", advs: []Advisory{{ID: "CVE-2023-23752", CVSS: 5.3}}}
	cache := NewMemoryCache(time.Hour)

	m := NewMultiFetcher([]CVEFetcher{p}, WithCache(cache))
	q := Query{Product: "joomla", Version: "4.2.7"}

	if _, err := m.Fetch(context.Background(), q); err != nil {
		t.Fatalf("first Fetch: %v", err)
	}
	if _, err := m.Fetch(context.Background(), q); err != nil {
		t.Fatalf("second Fetch: %v", err)
	}

	if p.calls != 1 {
		t.Fatalf("provider called %d times, want 1 (second call should hit cache)", p.calls)
	}
}

func TestDedupeAdvisoriesMergesSameCVE(t *testing.T) {
	in := []Advisory{
		{ID: "CVE-2023-23752", CVSS: 0, Description: "short", Source: "github",
			References: []string{"https://github.example/a"}},
		{ID: "cve-2023-23752", CVSS: 5.3, Severity: "MEDIUM",
			Description: "a considerably longer and more useful description",
			Source:      "nvd", References: []string{"https://nvd.example/b"}},
	}

	got := DedupeAdvisories(in)

	if len(got) != 1 {
		t.Fatalf("got %d advisories, want 1", len(got))
	}
	m := got[0]
	if m.ID != "CVE-2023-23752" {
		t.Errorf("ID = %q, want normalized uppercase", m.ID)
	}
	if m.CVSS != 5.3 {
		t.Errorf("CVSS = %v, want 5.3 (should adopt the scored record)", m.CVSS)
	}
	if m.Description != "a considerably longer and more useful description" {
		t.Errorf("Description = %q, want the longer one", m.Description)
	}
	if len(m.References) != 2 {
		t.Errorf("References = %v, want both merged", m.References)
	}
}

func TestAdvisoryAffectsVersion(t *testing.T) {
	a := Advisory{
		ID:     "CVE-2024-21726",
		Ranges: []VersionRange{{Introduced: "4.0.0", Fixed: "4.4.3"}, {Introduced: "5.0.0", Fixed: "5.0.3"}},
	}

	if !a.AffectsVersion("4.4.2") {
		t.Error("4.4.2 should be affected")
	}
	if !a.AffectsVersion("5.0.2") {
		t.Error("5.0.2 should be affected (second range)")
	}
	if a.AffectsVersion("5.0.3") {
		t.Error("5.0.3 is patched and should not be affected")
	}
	if a.AffectsVersion("3.9.0") {
		t.Error("3.9.0 is outside both ranges")
	}
}

func TestOfflineFetcherImplementsInterface(t *testing.T) {
	var _ CVEFetcher = NewOfflineFetcher(nil)
	var _ CVEFetcher = NewNVDProvider()
	var _ CVEFetcher = NewGitHubProvider()
	var _ CVEFetcher = NewMultiFetcher(nil)
}

// TestNVDProviderParsesResponse exercises the wire-format decoding against a
// stubbed NVD server, so no network access is needed.
func TestNVDProviderParsesResponse(t *testing.T) {
	const payload = `{
      "resultsPerPage": 1, "totalResults": 1,
      "vulnerabilities": [{"cve": {
        "id": "CVE-2023-23752",
        "published": "2023-02-16T18:15:11.163",
        "lastModified": "2023-03-01T00:00:00.000",
        "descriptions": [{"lang":"en","value":"An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints."}],
        "metrics": {"cvssMetricV31":[{"cvssData":{"baseScore":5.3,"baseSeverity":"MEDIUM","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}}]},
        "references": [{"url":"https://example.test/advisory"}],
        "configurations": [{"nodes":[{"cpeMatch":[
           {"vulnerable":true,"criteria":"cpe:2.3:a:joomla:joomla\\!:*:*:*:*:*:*:*:*",
            "versionStartIncluding":"4.0.0","versionEndIncluding":"4.2.7"}
        ]}]}]
      }}]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(payload))
	}))
	defer srv.Close()

	p := NewNVDProvider(WithNVDBaseURL(srv.URL), WithNVDHTTPClient(srv.Client()))

	advs, err := p.Fetch(context.Background(), Query{Product: "joomla", Version: "4.2.7"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(advs) != 1 {
		t.Fatalf("got %d advisories, want 1", len(advs))
	}

	a := advs[0]
	if a.ID != "CVE-2023-23752" {
		t.Errorf("ID = %q", a.ID)
	}
	if a.CVSS != 5.3 || a.Severity != "MEDIUM" {
		t.Errorf("CVSS = %v %q, want 5.3 MEDIUM", a.CVSS, a.Severity)
	}
	if !a.AffectsVersion("4.2.7") {
		t.Error("4.2.7 should match the parsed range")
	}
	if a.AffectsVersion("4.3.0") {
		t.Error("4.3.0 should be outside the parsed range")
	}
}

func TestNVDProviderHandlesThrottling(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	p := NewNVDProvider(WithNVDBaseURL(srv.URL), WithNVDHTTPClient(srv.Client()))

	_, err := p.Fetch(context.Background(), Query{Product: "joomla"})
	if err == nil {
		t.Fatal("expected an error for a 403 response")
	}
}

func TestGitHubProviderParsesResponse(t *testing.T) {
	const payload = `[{
      "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
      "cve_id": "CVE-2024-21726",
      "summary": "Joomla XSS via inadequate content filtering",
      "description": "Inadequate content filtering leads to XSS vulnerabilities.",
      "severity": "medium",
      "published_at": "2024-02-29T00:00:00Z",
      "updated_at": "2024-03-01T00:00:00Z",
      "html_url": "https://github.example/advisory",
      "cvss": {"score": 6.5, "vector_string": "CVSS:3.1/AV:N"},
      "references": ["https://example.test/ref"],
      "vulnerabilities": [{
        "package": {"ecosystem":"composer","name":"joomla/joomla-cms"},
        "vulnerable_version_range": ">= 4.0.0, < 4.4.3",
        "first_patched_version": "4.4.3"
      }]
    }]`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(payload))
	}))
	defer srv.Close()

	p := NewGitHubProvider(WithGitHubBaseURL(srv.URL), WithGitHubHTTPClient(srv.Client()))

	advs, err := p.Fetch(context.Background(), Query{Product: "joomla", Version: "4.4.0"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(advs) != 1 {
		t.Fatalf("got %d advisories, want 1", len(advs))
	}

	a := advs[0]
	if a.ID != "CVE-2024-21726" {
		t.Errorf("ID = %q, want the CVE id (not the GHSA id)", a.ID)
	}
	if !a.AffectsVersion("4.4.0") {
		t.Error("4.4.0 should match the constraint range")
	}
	if a.AffectsVersion("4.4.3") {
		t.Error("4.4.3 is patched and should not match")
	}
}
