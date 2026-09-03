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

// NVDBaseURL is the NVD CVE API v2 endpoint.
const NVDBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// nvdMaxBody bounds the NVD response we buffer.
const nvdMaxBody = 16 << 20

// NVDProvider queries the NIST National Vulnerability Database.
//
// Rate limits (NVD published): 5 requests / 30s without an API key,
// 50 requests / 30s with one. We self-limit accordingly so a scan does not
// get the operator's IP throttled or blocked.
type NVDProvider struct {
	BaseURL string
	APIKey  string
	Client  *http.Client

	limiter *rate.Limiter
}

// NVDOption configures an NVDProvider.
type NVDOption func(*NVDProvider)

// WithNVDAPIKey sets the API key explicitly.
func WithNVDAPIKey(key string) NVDOption {
	return func(p *NVDProvider) { p.APIKey = key }
}

// WithNVDBaseURL overrides the endpoint (used by tests).
func WithNVDBaseURL(u string) NVDOption {
	return func(p *NVDProvider) { p.BaseURL = u }
}

// WithNVDHTTPClient injects an HTTP client.
func WithNVDHTTPClient(c *http.Client) NVDOption {
	return func(p *NVDProvider) { p.Client = c }
}

// NewNVDProvider creates an NVD provider. The API key is read from the
// NVD_API_KEY environment variable when not supplied.
func NewNVDProvider(opts ...NVDOption) *NVDProvider {
	p := &NVDProvider{
		BaseURL: NVDBaseURL,
		APIKey:  os.Getenv("NVD_API_KEY"),
		Client:  defaultAPIClient(),
	}
	for _, opt := range opts {
		opt(p)
	}

	// 5 req / 30s = 0.166 rps unauthenticated; 50 req / 30s = 1.66 rps keyed.
	if p.APIKey != "" {
		p.limiter = rate.NewLimiter(rate.Limit(50.0/30.0), 5)
	} else {
		p.limiter = rate.NewLimiter(rate.Limit(5.0/30.0), 2)
	}
	return p
}

// Name implements CVEFetcher.
func (p *NVDProvider) Name() string { return "nvd" }

// Fetch implements CVEFetcher.
func (p *NVDProvider) Fetch(ctx context.Context, q Query) ([]Advisory, error) {
	if err := p.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("nvd rate limiter: %w", err)
	}

	endpoint, err := p.buildURL(q)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("building NVD request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", apiUserAgent)
	if p.APIKey != "" {
		req.Header.Set("apiKey", p.APIKey)
	}

	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying NVD: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, nvdMaxBody))
	if err != nil {
		return nil, fmt.Errorf("reading NVD response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden, http.StatusTooManyRequests:
		return nil, fmt.Errorf("NVD throttled the request (status %d); set NVD_API_KEY for a higher quota", resp.StatusCode)
	case http.StatusNotFound:
		return nil, nil
	default:
		return nil, fmt.Errorf("NVD returned status %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	var payload nvdResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decoding NVD response: %w", err)
	}

	out := make([]Advisory, 0, len(payload.Vulnerabilities))
	for _, v := range payload.Vulnerabilities {
		if adv, ok := v.CVE.toAdvisory(); ok {
			out = append(out, adv)
		}
	}
	return out, nil
}

// buildURL prefers a CPE-based match (accurate version filtering by NVD
// itself) and falls back to a keyword search when no usable version is known.
func (p *NVDProvider) buildURL(q Query) (string, error) {
	base := p.BaseURL
	if base == "" {
		base = NVDBaseURL
	}

	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("invalid NVD base URL %q: %w", base, err)
	}

	params := url.Values{}
	params.Set("resultsPerPage", "200")

	product := strings.ToLower(strings.TrimSpace(q.Product))
	if product == "" {
		product = "joomla"
	}

	switch {
	case IsVersionComplete(q.Version) && product == "joomla":
		// The Joomla CPE product is literally "joomla\!".
		params.Set("virtualMatchString", fmt.Sprintf(`cpe:2.3:a:joomla:joomla\!:%s`, q.Version))
	case q.Component != "":
		params.Set("keywordSearch", product+" "+q.Component)
	default:
		kw := product
		if q.Version != "" {
			kw += " " + q.Version
		}
		params.Set("keywordSearch", kw)
	}

	u.RawQuery = params.Encode()
	return u.String(), nil
}

// --- NVD API v2 wire format ---

type nvdResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics    nvdMetrics `json:"metrics"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	Configurations []struct {
		Nodes []struct {
			CPEMatch []nvdCPEMatch `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
}

type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type nvdMetrics struct {
	CVSSMetricV31 []nvdCVSSMetric `json:"cvssMetricV31"`
	CVSSMetricV30 []nvdCVSSMetric `json:"cvssMetricV30"`
	CVSSMetricV2  []nvdCVSSMetric `json:"cvssMetricV2"`
}

type nvdCVSSMetric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
}

func (c nvdCVE) toAdvisory() (Advisory, bool) {
	if strings.TrimSpace(c.ID) == "" {
		return Advisory{}, false
	}

	adv := Advisory{
		ID:     strings.ToUpper(c.ID),
		Source: "nvd",
		References: func() []string {
			refs := make([]string, 0, len(c.References)+1)
			refs = append(refs, "https://nvd.nist.gov/vuln/detail/"+c.ID)
			for _, r := range c.References {
				refs = append(refs, r.URL)
			}
			return dedupeStrings(refs)
		}(),
	}

	for _, d := range c.Descriptions {
		if strings.EqualFold(d.Lang, "en") {
			adv.Description = d.Value
			break
		}
	}
	if adv.Description == "" && len(c.Descriptions) > 0 {
		adv.Description = c.Descriptions[0].Value
	}
	adv.Title = firstSentence(adv.Description, 120)

	score, severity, vector := c.Metrics.best()
	adv.CVSS = score
	adv.Severity = severity
	adv.CVSSVector = vector

	adv.Published = parseNVDTime(c.Published)
	adv.Modified = parseNVDTime(c.LastModified)

	for _, cfg := range c.Configurations {
		for _, node := range cfg.Nodes {
			for _, m := range node.CPEMatch {
				if !m.Vulnerable {
					continue
				}
				r := VersionRange{
					Introduced:   firstNonEmpty(m.VersionStartIncluding, m.VersionStartExcluding),
					Fixed:        m.VersionEndExcluding,
					LastAffected: m.VersionEndIncluding,
				}
				if r.Introduced == "" && r.Fixed == "" && r.LastAffected == "" {
					// Fall back to the exact version pinned in the CPE string.
					if v := cpeVersion(m.Criteria); v != "" && v != "*" && v != "-" {
						r.Introduced, r.LastAffected = v, v
					}
				}
				if r.Introduced != "" || r.Fixed != "" || r.LastAffected != "" {
					adv.Ranges = append(adv.Ranges, r)
				}
			}
		}
	}

	return adv, true
}

// best returns the highest-priority CVSS metric available (v3.1 > v3.0 > v2).
func (m nvdMetrics) best() (score float64, severity, vector string) {
	for _, set := range [][]nvdCVSSMetric{m.CVSSMetricV31, m.CVSSMetricV30, m.CVSSMetricV2} {
		if len(set) == 0 {
			continue
		}
		e := set[0]
		sev := e.CVSSData.BaseSeverity
		if sev == "" {
			sev = e.BaseSeverity
		}
		return e.CVSSData.BaseScore, strings.ToUpper(sev), e.CVSSData.VectorString
	}
	return 0, "", ""
}

// cpeVersion pulls the version field out of a CPE 2.3 string.
// cpe:2.3:a:joomla:joomla\!:3.9.4:*:*:*:*:*:*:* -> "3.9.4"
func cpeVersion(criteria string) string {
	parts := strings.Split(criteria, ":")
	if len(parts) < 6 {
		return ""
	}
	return parts[5]
}

func parseNVDTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05.000",
		"2006-01-02T15:04:05",
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
