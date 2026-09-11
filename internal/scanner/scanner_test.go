package scanner

import (
	"bytes"
	"context"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

func TestCredentialAttemptsAreReportedAndSessionTrafficIsCounted(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	loginPage := `<html><body><form>` +
		`<input name="username"><input name="passwd" type="password">` +
		`<input type="hidden" name="` + token + `" value="1">` +
		`</form></body></html>`

	var (
		posts   atomic.Int32
		badForm atomic.Bool
	)
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte(joomlaHome))
		case "/administrator/manifests/files/joomla.xml":
			w.Write([]byte(manifest))
		case "/administrator/index.php":
			if r.Method == nethttp.MethodPost {
				posts.Add(1)
				if err := r.ParseForm(); err != nil || r.PostForm.Get(token) != "1" || r.PostForm.Get("username") != "admin" {
					badForm.Store(true)
				}
			} else {
				nethttp.SetCookie(w, &nethttp.Cookie{Name: "jsession", Value: "test", Path: "/"})
			}
			w.Write([]byte(loginPage))
		default:
			nethttp.NotFound(w, r)
		}
	}))
	defer srv.Close()

	var logs bytes.Buffer
	s, err := NewScanner(ScanConfig{
		Target:              srv.URL,
		Threads:             2,
		Timeout:             5 * time.Second,
		RateLimit:           200,
		FollowRedirects:     true,
		CheckVersion:        true,
		EnableBruteForce:    true,
		SkipUserEnumeration: true,
		KnownUsers:          []string{"admin"},
		PasswordWordlist:    []string{"wrong-one", "wrong-two"},
		Verbose:             true,
		LogWriter:           &logs,
	})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	result := s.Scan(context.Background())

	if got := posts.Load(); got != 2 {
		t.Fatalf("login POSTs = %d, want 2", got)
	}
	if badForm.Load() {
		t.Fatal("login POST omitted the username or CSRF token")
	}
	if result.Metadata.CredentialAttempts != 2 || result.Metadata.CredentialErrors != 0 || result.Metadata.CredentialsFound != 0 {
		t.Fatalf("credential metadata = attempts %d, errors %d, found %d; want 2, 0, 0",
			result.Metadata.CredentialAttempts, result.Metadata.CredentialErrors,
			result.Metadata.CredentialsFound)
	}
	if len(result.Users) != 1 || result.Users[0].Method != "operator-supplied" || result.Users[0].PasswordAttempts != 2 {
		t.Fatalf("unexpected user result: %+v", result.Users)
	}
	// Detection performs three requests; two failed credential attempts perform
	// GET + POST + verification GET each. Session traffic must be included.
	if result.Metadata.HTTPRequests != 9 {
		t.Fatalf("HTTPRequests = %d, want 9 including isolated login sessions", result.Metadata.HTTPRequests)
	}
	for _, want := range []string{
		"Password progress for admin: 1/2 attempts completed",
		"No valid password found for user: admin after 2 attempts",
	} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("verbose log does not contain %q:\n%s", want, logs.String())
		}
	}
}

func TestCredentialRequestErrorsAreReportedAsInconclusive(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	loginPage := `<html><body><form>` +
		`<input name="username"><input name="passwd" type="password">` +
		`<input type="hidden" name="` + token + `" value="1">` +
		`</form></body></html>`

	var posts atomic.Int32
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte(joomlaHome))
		case "/administrator/manifests/files/joomla.xml":
			w.Write([]byte(manifest))
		case "/administrator/index.php":
			if r.Method == nethttp.MethodPost && posts.Add(1) == 1 {
				w.WriteHeader(nethttp.StatusInternalServerError)
				return
			}
			w.Write([]byte(loginPage))
		default:
			nethttp.NotFound(w, r)
		}
	}))
	defer srv.Close()

	var logs bytes.Buffer
	s, err := NewScanner(ScanConfig{
		Target:              srv.URL,
		Threads:             1,
		Timeout:             5 * time.Second,
		RateLimit:           200,
		FollowRedirects:     true,
		CheckVersion:        true,
		EnableBruteForce:    true,
		SkipUserEnumeration: true,
		KnownUsers:          []string{"admin"},
		PasswordWordlist:    []string{"first", "second"},
		Verbose:             true,
		LogWriter:           &logs,
	})
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}

	result := s.Scan(context.Background())

	if result.Metadata.CredentialAttempts != 2 || result.Metadata.CredentialErrors != 1 {
		t.Fatalf("credential metadata = attempts %d, errors %d; want 2, 1",
			result.Metadata.CredentialAttempts, result.Metadata.CredentialErrors)
	}
	if result.Metadata.HTTPRequests != 8 || result.Metadata.HTTPErrors != 1 {
		t.Fatalf("HTTP metadata = requests %d, errors %d; want 8, 1",
			result.Metadata.HTTPRequests, result.Metadata.HTTPErrors)
	}
	if len(result.Users) != 1 || result.Users[0].PasswordAttempts != 2 || result.Users[0].PasswordErrors != 1 {
		t.Fatalf("unexpected user result: %+v", result.Users)
	}
	if len(result.Metadata.Warnings) != 1 || !strings.Contains(result.Metadata.Warnings[0], "1 of 2 password checks were inconclusive") {
		t.Fatalf("unexpected warnings: %v", result.Metadata.Warnings)
	}
	if !strings.Contains(logs.String(),
		"No valid password confirmed for user: admin after 2 attempts (1 conclusive, 1 inconclusive)") {
		t.Fatalf("verbose log did not explain the partial result:\n%s", logs.String())
	}
}
