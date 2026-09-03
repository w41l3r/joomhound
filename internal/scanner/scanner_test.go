package scanner

import (
	"context"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const joomlaHome = `<!DOCTYPE html><html><head>
<meta name="generator" content="Joomla! - Open Source Content Management">
<script src="/media/system/js/core.min.js"></script>
</head><body>Joomla.submitbutton</body></html>`

const manifest = `<extension type="file"><version>3.7.0</version></extension>`

func joomlaTestServer() *httptest.Server {
	return httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		switch {
		case r.URL.Path == "/":
			w.Write([]byte(joomlaHome))
		case r.URL.Path == "/administrator/manifests/files/joomla.xml":
			w.Write([]byte(manifest))
		case strings.Contains(r.URL.Path, "com_fields"):
			w.WriteHeader(403)
		default:
			nethttp.NotFound(w, r)
		}
	}))
}

func TestScannerRequiresTarget(t *testing.T) {
	if _, err := NewScanner(ScanConfig{}); err == nil {
		t.Fatal("expected an error for an empty target")
	}
}

func TestScannerInvalidProxyIsReported(t *testing.T) {
	_, err := NewScanner(ScanConfig{Target: "http://x.tld", ProxyURL: "gopher://bad"})
	if err == nil {
		t.Fatal("expected an error for an unsupported proxy scheme")
	}
}

// TestFullScanOffline runs the whole pipeline against a fake Joomla target
// with the offline CVE database, asserting the version-to-CVE correlation.
func TestFullScanOffline(t *testing.T) {
	srv := joomlaTestServer()
	defer srv.Close()

	s, err := NewScanner(ScanConfig{
		Target:          srv.URL,
		Threads:         4,
		Timeout:         5 * time.Second,
		RateLimit:       200,
		FollowRedirects: true,
		CheckVersion:    true,
		CheckComponents: true,
		CheckTemplates:  true,
		CheckCVEs:       true,
	})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	result := s.Scan(context.Background())

	if !result.JoomlaDetected {
		t.Fatal("Joomla was not detected")
	}
	if result.Version.Version != "3.7.0" {
		t.Fatalf("Version = %q, want 3.7.0", result.Version.Version)
	}

	// 3.7.0 is affected by CVE-2017-8917.
	var found bool
	for _, v := range result.Vulnerabilities {
		if v.CVE == "CVE-2017-8917" {
			found = true
			if v.Confidence == "" {
				t.Error("vulnerability is missing a confidence label")
			}
		}
	}
	if !found {
		t.Errorf("CVE-2017-8917 not correlated for 3.7.0; got %+v", result.Vulnerabilities)
	}

	// HTTPRequests used to be hardcoded to 0.
	if result.Metadata.HTTPRequests == 0 {
		t.Error("Metadata.HTTPRequests was not populated")
	}
	if result.Metadata.CVESource != "offline" {
		t.Errorf("CVESource = %q, want offline", result.Metadata.CVESource)
	}
}

func TestScanCancellation(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Write([]byte(joomlaHome))
	}))
	defer srv.Close()

	s, err := NewScanner(ScanConfig{
		Target:          srv.URL,
		Threads:         4,
		Timeout:         5 * time.Second,
		RateLimit:       200,
		CheckComponents: true,
		CheckTemplates:  true,
	})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	s.Scan(ctx)

	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("scan took %s after cancellation", elapsed)
	}
}

func TestScanNonJoomlaTargetStopsEarly(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><head><meta name="viewport" content="width=device-width"></head><body>hi</body></html>`))
	}))
	defer srv.Close()

	s, err := NewScanner(ScanConfig{
		Target:          srv.URL,
		Threads:         2,
		RateLimit:       200,
		CheckVersion:    true,
		CheckComponents: true,
	})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	result := s.Scan(context.Background())

	if result.JoomlaDetected {
		t.Fatal("non-Joomla target reported as Joomla")
	}
	if len(result.Components) != 0 {
		t.Error("components should not be enumerated when Joomla is not detected")
	}
}
