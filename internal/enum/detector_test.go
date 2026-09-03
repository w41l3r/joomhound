package enum

import (
	"context"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/w41l3r/joomhound/internal/http"
)

func testDetector(t *testing.T) *Detector {
	t.Helper()
	c, err := http.NewClient(http.ClientConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	d := NewDetector(c)
	d.SetThreads(4)
	return d
}

// nonJoomlaPage is an ordinary modern website. The original detector matched
// on `<meta property="og:image">` and `name="viewport"`, so it reported this
// page - and essentially every site on the internet - as Joomla.
const nonJoomlaPage = `<!DOCTYPE html><html><head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta property="og:image" content="/img/social.png">
<meta name="generator" content="WordPress 6.4">
<title>A WordPress site</title>
</head><body><h1>Hello</h1></body></html>`

const joomlaPage = `<!DOCTYPE html><html><head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="Joomla! - Open Source Content Management">
<script src="/media/system/js/core.min.js"></script>
</head><body>
<script>jQuery(document).ready(function(){ Joomla.submitbutton('save'); });</script>
</body></html>`

const coreManifest = `<?xml version="1.0" encoding="UTF-8"?>
<extension type="file" method="upgrade">
  <name>files_joomla</name>
  <version>4.2.7</version>
</extension>`

// TestDetectJoomlaNoFalsePositive is the key regression test.
func TestDetectJoomlaNoFalsePositive(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if r.URL.Path == "/" {
			w.Write([]byte(nonJoomlaPage))
			return
		}
		nethttp.NotFound(w, r)
	}))
	defer srv.Close()

	detected, signals := testDetector(t).DetectJoomla(context.Background(), srv.URL)
	if detected {
		t.Fatalf("non-Joomla site reported as Joomla (signals: %v)", signals)
	}
}

func TestDetectJoomlaTruePositive(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte(joomlaPage))
		case "/administrator/manifests/files/joomla.xml":
			w.Write([]byte(coreManifest))
		default:
			nethttp.NotFound(w, r)
		}
	}))
	defer srv.Close()

	detected, signals := testDetector(t).DetectJoomla(context.Background(), srv.URL)
	if !detected {
		t.Fatal("Joomla site was not detected")
	}
	if len(signals) < 2 {
		t.Errorf("expected multiple signals, got %v", signals)
	}
}

func TestDetectVersionFromManifest(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if r.URL.Path == "/administrator/manifests/files/joomla.xml" {
			w.Write([]byte(coreManifest))
			return
		}
		nethttp.NotFound(w, r)
	}))
	defer srv.Close()

	info := testDetector(t).DetectVersion(context.Background(), srv.URL)
	if !info.Detected {
		t.Fatal("version not detected")
	}
	if info.Version != "4.2.7" {
		t.Fatalf("Version = %q, want 4.2.7", info.Version)
	}
	if info.Confidence < 0.9 {
		t.Errorf("Confidence = %v, want high confidence for a manifest match", info.Confidence)
	}
}

// TestHomepageFetchedOnce covers the response cache: the old detector issued
// four separate GETs of the site root during fingerprinting alone.
func TestHomepageFetchedOnce(t *testing.T) {
	var rootHits atomic.Int32

	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if r.URL.Path == "/" {
			rootHits.Add(1)
			w.Write([]byte(joomlaPage))
			return
		}
		nethttp.NotFound(w, r)
	}))
	defer srv.Close()

	d := testDetector(t)
	ctx := context.Background()

	d.DetectJoomla(ctx, srv.URL)
	d.DetectVersion(ctx, srv.URL)

	if n := rootHits.Load(); n != 1 {
		t.Fatalf("site root fetched %d times, want 1 (response cache)", n)
	}
}

// TestComponentPathHasNoDoublePrefix is the regression for building
// /administrator/components/com_com_contact/ from a list that already
// contained "com_" prefixed names.
func TestComponentPathHasNoDoublePrefix(t *testing.T) {
	var badPath atomic.Bool

	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if strings.Contains(r.URL.Path, "com_com_") {
			badPath.Store(true)
		}
		nethttp.NotFound(w, r)
	}))
	defer srv.Close()

	testDetector(t).EnumerateComponents(context.Background(), srv.URL)

	if badPath.Load() {
		t.Fatal("detector requested a path containing com_com_")
	}
}

// TestComponentEnumerationHandlesSoft404 verifies that a catch-all 200 target
// does not produce a "every component installed" report.
func TestComponentEnumerationHandlesSoft404(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		// Everything returns 200 with identical content.
		w.WriteHeader(200)
		w.Write([]byte("<html><body>Not Found</body></html>"))
	}))
	defer srv.Close()

	comps := testDetector(t).EnumerateComponents(context.Background(), srv.URL)
	if len(comps) != 0 {
		t.Fatalf("soft-404 target yielded %d components, want 0", len(comps))
	}
}

// TestComponentEnumerationAccepts403 checks that a Forbidden component
// directory counts as present - the old code required exactly 200.
func TestComponentEnumerationAccepts403(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if strings.Contains(r.URL.Path, "com_content") {
			w.WriteHeader(403)
			return
		}
		nethttp.NotFound(w, r)
	}))
	defer srv.Close()

	comps := testDetector(t).EnumerateComponents(context.Background(), srv.URL)
	if len(comps) != 1 || comps[0].Name != "com_content" {
		t.Fatalf("got %+v, want com_content detected via 403", comps)
	}
}

func TestEnumerateComponentsRespectsCancellation(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		time.Sleep(50 * time.Millisecond)
		nethttp.NotFound(w, r)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	start := time.Now()
	testDetector(t).EnumerateComponents(ctx, srv.URL)

	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("enumeration took %s after cancellation", elapsed)
	}
}

func TestNormalizeTarget(t *testing.T) {
	tests := map[string]string{
		"https://a.tld/":   "https://a.tld",
		"https://a.tld///": "https://a.tld",
		"a.tld":            "http://a.tld",
		"http://a.tld/x/":  "http://a.tld/x",
	}
	for in, want := range tests {
		if got := NormalizeTarget(in); got != want {
			t.Errorf("NormalizeTarget(%q) = %q, want %q", in, got, want)
		}
	}
}
