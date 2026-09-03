package cve

import (
	"net"
	"net/http"
	"strings"
	"time"
)

const apiUserAgent = "JoomHound/1.0 (+https://github.com/w41l3r/joomhound)"

// defaultAPIClient builds the HTTP client used for CVE feed lookups.
//
// It deliberately does NOT reuse the scan's HTTP client:
//   - the scan client is rate-limited for the *target*, not for NVD/GitHub;
//   - the scan client routes through the engagement proxy (Burp), which would
//     leak lookup traffic into the proxy history and may not reach the internet;
//   - the scan client runs with InsecureSkipVerify, which must never apply to
//     a public CVE feed.
//
// It honours HTTP_PROXY/HTTPS_PROXY/NO_PROXY so an operator behind a corporate
// egress proxy still gets lookups.
func defaultAPIClient() *http.Client {
	return &http.Client{
		Timeout: 25 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     60 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			ForceAttemptHTTP2:   true,
		},
	}
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// firstSentence derives a short title from a description.
func firstSentence(s string, max int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if s == "" {
		return ""
	}
	if i := strings.Index(s, ". "); i > 0 && i < max {
		return s[:i]
	}
	return truncate(s, max)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
