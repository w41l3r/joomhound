package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// GitHubAdvisoryBaseURL is the public GitHub Advisory Database REST endpoint.
// It works unauthenticated (60 req/h per IP); a token raises the limit to
// 5000 req/h and is read from GITHUB_TOKEN.
const GitHubAdvisoryBaseURL = "https://api.github.com/advisories"

const ghMaxBody = 16 << 20

// GitHubProvider queries the GitHub Advisory Database. It complements NVD:
// GHSA records usually carry precise, machine-readable affected-version
// ranges for the joomla/joomla-cms Composer package, whereas NVD relies on
// CPE data that is often coarse or late.
type GitHubProvider struct {
	BaseURL string
	Token   string
	Client  *http.Client

	// Package is the Composer package to filter on. Defaults to
	// "joomla/joomla-cms".
	Package string

	limiter *rate.Limiter
}

// GitHubOption configures a GitHubProvider.
type GitHubOption func(*GitHubProvider)

// WithGitHubToken sets the API token explicitly.
func WithGitHubToken(t string) GitHubOption {
	return func(p *GitHubProvider) { p.Token = t }
}

// WithGitHubBaseURL overrides the endpoint (used by tests).
func WithGitHubBaseURL(u string) GitHubOption {
	return func(p *GitHubProvider) { p.BaseURL = u }
}

// WithGitHubHTTPClient injects an HTTP client.
func WithGitHubHTTPClient(c *http.Client) GitHubOption {
	return func(p *GitHubProvider) { p.Client = c }
}

// NewGitHubProvider creates a GitHub Advisory Database provider.
func NewGitHubProvider(opts ...GitHubOption) *GitHubProvider {
	p := &GitHubProvider{
		BaseURL: GitHubAdvisoryBaseURL,
		Token:   os.Getenv("GITHUB_TOKEN"),
		Client:  defaultAPIClient(),
		Package: "joomla/joomla-cms",
	}
	for _, opt := range opts {
		opt(p)
	}
	if p.Token != "" {
		p.limiter = rate.NewLimiter(rate.Limit(5), 5)
	} else {
		p.limiter = rate.NewLimiter(rate.Limit(1), 2)
	}
	return p
}

// Name implements CVEFetcher.
func (p *GitHubProvider) Name() string { return "github" }

// Fetch implements CVEFetcher.
func (p *GitHubProvider) Fetch(ctx context.Context, q Query) ([]Advisory, error) {
	if err := p.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("github rate limiter: %w", err)
	}

	endpoint, err := p.buildURL(q)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("building GitHub request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", apiUserAgent)
	if p.Token != "" {
		req.Header.Set("Authorization", "Bearer "+p.Token)
	}

	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying GitHub advisories: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, ghMaxBody))
	if err != nil {
		return nil, fmt.Errorf("reading GitHub response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden, http.StatusTooManyRequests:
		return nil, fmt.Errorf("GitHub rate limit hit (status %d); set GITHUB_TOKEN to raise it", resp.StatusCode)
	case http.StatusNotFound:
		return nil, nil
	default:
		return nil, fmt.Errorf("GitHub returned status %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	var raw []ghAdvisory
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decoding GitHub response: %w", err)
	}

	out := make([]Advisory, 0, len(raw))
	for _, a := range raw {
		if adv, ok := a.toAdvisory(p.Package); ok {
			out = append(out, adv)
		}
	}
	return out, nil
}

func (p *GitHubProvider) buildURL(q Query) (string, error) {
	base := p.BaseURL
	if base == "" {
		base = GitHubAdvisoryBaseURL
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("invalid GitHub base URL %q: %w", base, err)
	}

	pkg := p.Package
	if pkg == "" {
		pkg = "joomla/joomla-cms"
	}

	params := url.Values{}
	params.Set("ecosystem", "composer")
	params.Set("affects", pkg)
	params.Set("per_page", "100")
	// Newest first so a truncated page still holds the most relevant records.
	params.Set("sort", "published")
	params.Set("direction", "desc")

	u.RawQuery = params.Encode()
	return u.String(), nil
}

// --- GitHub advisories wire format ---

type ghAdvisory struct {
	GHSAID      string `json:"ghsa_id"`
	CVEID       string `json:"cve_id"`
	Summary     string `json:"summary"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	PublishedAt string `json:"published_at"`
	UpdatedAt   string `json:"updated_at"`
	HTMLURL     string `json:"html_url"`
	CVSS        struct {
		Score        float64 `json:"score"`
		VectorString string  `json:"vector_string"`
	} `json:"cvss"`
	References  []string `json:"references"`
	Identifiers []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"identifiers"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		VulnerableVersionRange string `json:"vulnerable_version_range"`
		FirstPatchedVersion    string `json:"first_patched_version"`
	} `json:"vulnerabilities"`
}

func (a ghAdvisory) toAdvisory(wantPkg string) (Advisory, bool) {
	// Prefer the CVE ID so records merge cleanly with NVD; fall back to GHSA
	// for advisories that never got a CVE assigned.
	id := strings.ToUpper(strings.TrimSpace(a.CVEID))
	if id == "" {
		id = strings.ToUpper(strings.TrimSpace(a.GHSAID))
	}
	if id == "" {
		return Advisory{}, false
	}

	adv := Advisory{
		ID:          id,
		Title:       a.Summary,
		Description: a.Description,
		CVSS:        a.CVSS.Score,
		CVSSVector:  a.CVSS.VectorString,
		Severity:    strings.ToUpper(a.Severity),
		Source:      "github",
		Published:   parseGHTime(a.PublishedAt),
		Modified:    parseGHTime(a.UpdatedAt),
	}

	refs := append([]string{}, a.References...)
	if a.HTMLURL != "" {
		refs = append(refs, a.HTMLURL)
	}
	adv.References = dedupeStrings(refs)

	var aliases []string
	if a.GHSAID != "" && a.GHSAID != id {
		aliases = append(aliases, a.GHSAID)
	}
	for _, ident := range a.Identifiers {
		if v := strings.ToUpper(strings.TrimSpace(ident.Value)); v != "" && v != id {
			aliases = append(aliases, v)
		}
	}
	adv.Aliases = dedupeStrings(aliases)

	for _, v := range a.Vulnerabilities {
		// The API's `affects` filter is not always exact, so re-check the
		// package name to avoid importing ranges for an unrelated package.
		if wantPkg != "" && !strings.EqualFold(v.Package.Name, wantPkg) {
			continue
		}
		r := VersionRange{
			Constraint: strings.TrimSpace(v.VulnerableVersionRange),
			Fixed:      strings.TrimSpace(v.FirstPatchedVersion),
		}
		if r.Constraint != "" || r.Fixed != "" {
			adv.Ranges = append(adv.Ranges, r)
		}
	}

	if adv.Title == "" {
		adv.Title = firstSentence(adv.Description, 120)
	}

	return adv, true
}

func parseGHTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}
