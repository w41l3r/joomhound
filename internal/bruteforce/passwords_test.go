package bruteforce

import (
	"context"
	"errors"
	"fmt"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/w41l3r/joomhound/internal/http"
)

const testToken = "0123456789abcdef0123456789abcdef"

const loginPage = `<html><body>
<form action="index.php" method="post">
  <input name="username" type="text">
  <input name="passwd" type="password">
  <input type="hidden" name="` + testToken + `" value="1">
</form></body></html>`

const dashboardPage = `<html><body>
<div id="sidebarmenu"></div>
<a href="index.php?option=com_login&task=logout">Log out</a>
<div>Control Panel</div>
</body></html>`

// fakeJoomla emulates a Joomla administrator login: it requires a session
// cookie AND the CSRF token, exactly like the real thing.
type fakeJoomla struct {
	validUser, validPass string

	mu       sync.Mutex
	loggedIn map[string]bool
	attempts int
	// lockoutAfter, when > 0, starts returning a lockout page.
	lockoutAfter int
}

func newFakeJoomla(user, pass string) *fakeJoomla {
	return &fakeJoomla{validUser: user, validPass: pass, loggedIn: map[string]bool{}}
}

func (f *fakeJoomla) handler() nethttp.Handler {
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		sess := ""
		if c, err := r.Cookie("jsession"); err == nil {
			sess = c.Value
		}

		if r.Method == nethttp.MethodGet {
			if sess == "" {
				sess = fmt.Sprintf("s%d", time.Now().UnixNano())
				nethttp.SetCookie(w, &nethttp.Cookie{Name: "jsession", Value: sess, Path: "/"})
			}
			f.mu.Lock()
			auth := f.loggedIn[sess]
			f.mu.Unlock()

			if auth {
				w.Write([]byte(dashboardPage))
				return
			}
			w.Write([]byte(loginPage))
			return
		}

		// POST
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(400)
			return
		}

		f.mu.Lock()
		f.attempts++
		locked := f.lockoutAfter > 0 && f.attempts > f.lockoutAfter
		f.mu.Unlock()

		if locked {
			w.Write([]byte(`<html><body>Too many failed login attempts. Please try again later.</body></html>`))
			return
		}

		// No session or no CSRF token => rejected before credentials matter.
		if sess == "" || r.PostForm.Get(testToken) != "1" {
			w.Write([]byte(loginPage))
			return
		}

		if r.PostForm.Get("username") == f.validUser && r.PostForm.Get("passwd") == f.validPass {
			f.mu.Lock()
			f.loggedIn[sess] = true
			f.mu.Unlock()
			w.Write([]byte(dashboardPage))
			return
		}

		w.Write([]byte(loginPage))
	})
}

func testClient(t *testing.T) *http.Client {
	t.Helper()
	c, err := http.NewClient(http.ClientConfig{
		EnableCookies: true,
		Timeout:       5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestExtractCSRFToken(t *testing.T) {
	got, ok := extractCSRFToken(loginPage)
	if !ok {
		t.Fatal("token not found in login page")
	}
	if got != testToken {
		t.Fatalf("token = %q, want %q", got, testToken)
	}

	if _, ok := extractCSRFToken("<html>no token here</html>"); ok {
		t.Error("expected no token in a page without one")
	}
}

// TestIsAuthenticated is the regression test for the old success heuristic,
// which matched "Home" and "Administrator" - both present on the login page -
// so any password could be reported as valid.
func TestIsAuthenticated(t *testing.T) {
	if isAuthenticated(loginPage) {
		t.Error("login page must not be treated as authenticated")
	}
	if !isAuthenticated(dashboardPage) {
		t.Error("dashboard should be treated as authenticated")
	}
	if isAuthenticated("") {
		t.Error("empty body must not be treated as authenticated")
	}
	// The exact strings that broke the old detector.
	if isAuthenticated(`<html><body><h1>Administrator</h1><a href="/">Home</a><input name="passwd"></body></html>`) {
		t.Error("a login page mentioning Administrator/Home must not count as success")
	}
}

// TestBruteForceFindsValidPassword exercises the full session + CSRF flow.
func TestBruteForceFindsValidPassword(t *testing.T) {
	fake := newFakeJoomla("admin", "correct-horse")
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	pb := NewPasswordBruteforcer(testClient(t), 2)

	res, err := pb.BruteForcePassword(context.Background(), srv.URL, "admin",
		[]string{"wrong1", "wrong2", "correct-horse", "wrong3"})
	if err != nil {
		t.Fatalf("BruteForcePassword: %v", err)
	}
	if !res.PasswordValid {
		t.Fatal("valid password was not found")
	}
	if res.Password != "correct-horse" {
		t.Fatalf("Password = %q, want %q", res.Password, "correct-horse")
	}
	if res.PasswordAttempts == 0 || int64(res.PasswordAttempts) != pb.Attempts() {
		t.Fatalf("PasswordAttempts = %d, cumulative Attempts = %d; want matching non-zero counts",
			res.PasswordAttempts, pb.Attempts())
	}
}

func TestBruteForceReportsNoFalsePositive(t *testing.T) {
	fake := newFakeJoomla("admin", "correct-horse")
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	pb := NewPasswordBruteforcer(testClient(t), 2)

	res, err := pb.BruteForcePassword(context.Background(), srv.URL, "admin",
		[]string{"wrong1", "wrong2", "wrong3"})
	if err != nil {
		t.Fatalf("BruteForcePassword: %v", err)
	}
	if res.PasswordValid {
		t.Fatalf("reported a false positive: %q", res.Password)
	}
	if res.PasswordAttempts != 3 {
		t.Fatalf("PasswordAttempts = %d, want 3", res.PasswordAttempts)
	}
	if res.PasswordErrors != 0 {
		t.Fatalf("PasswordErrors = %d, want 0", res.PasswordErrors)
	}
}

func TestBruteForceCountsRequestErrorsAsInconclusive(t *testing.T) {
	var posts atomic.Int32
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if r.Method == nethttp.MethodGet {
			w.Write([]byte(loginPage))
			return
		}
		if posts.Add(1) == 1 {
			w.WriteHeader(nethttp.StatusInternalServerError)
			return
		}
		w.Write([]byte(loginPage))
	}))
	defer srv.Close()

	pb := NewPasswordBruteforcer(testClient(t), 1)
	var messages []string
	pb.OnMessage = func(message string) { messages = append(messages, message) }
	res, err := pb.BruteForcePassword(context.Background(), srv.URL, "admin",
		[]string{"first", "second"})
	if err != nil {
		t.Fatalf("BruteForcePassword: %v", err)
	}
	if res.PasswordValid {
		t.Fatal("request failure must not be reported as a valid password")
	}
	if res.PasswordAttempts != 2 || res.PasswordErrors != 1 {
		t.Fatalf("password counters = attempts %d, errors %d; want 2, 1",
			res.PasswordAttempts, res.PasswordErrors)
	}
	if len(messages) != 1 || !strings.Contains(messages[0], "password check for admin was inconclusive: http status 500") {
		t.Fatalf("unexpected diagnostic messages: %v", messages)
	}
	if strings.Contains(messages[0], "first") {
		t.Fatalf("diagnostic message leaked the password candidate: %q", messages[0])
	}
}

// TestBruteForceAbortsOnLockout covers the new lockout detection.
func TestBruteForceAbortsOnLockout(t *testing.T) {
	fake := newFakeJoomla("admin", "never-tried")
	fake.lockoutAfter = 3
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	pb := NewPasswordBruteforcer(testClient(t), 1)

	passwords := make([]string, 100)
	for i := range passwords {
		passwords[i] = fmt.Sprintf("pw%d", i)
	}

	_, err := pb.BruteForcePassword(context.Background(), srv.URL, "admin", passwords)
	if !errors.Is(err, ErrAccountLockout) {
		t.Fatalf("err = %v, want ErrAccountLockout", err)
	}
	if n := pb.Attempts(); n > 20 {
		t.Fatalf("made %d attempts after lockout; should have stopped promptly", n)
	}
}

func TestBruteForceAbortsImmediatelyOnHTTP429(t *testing.T) {
	var posts atomic.Int32
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if r.Method == nethttp.MethodGet {
			w.Write([]byte(loginPage))
			return
		}
		posts.Add(1)
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(nethttp.StatusTooManyRequests)
	}))
	defer srv.Close()

	client, err := http.NewClient(http.ClientConfig{
		EnableCookies:  true,
		Timeout:        5 * time.Second,
		MaxRetries:     3,
		RetryBaseDelay: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	pb := NewPasswordBruteforcer(client, 1)

	start := time.Now()
	res, err := pb.BruteForcePassword(context.Background(), srv.URL, "admin",
		[]string{"one", "two", "three", "four"})
	if !errors.Is(err, ErrAccountLockout) {
		t.Fatalf("error = %v, want ErrAccountLockout", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("HTTP 429 took %s to abort; Retry-After must not delay credential testing", elapsed)
	}
	if got := posts.Load(); got != 1 {
		t.Fatalf("server saw %d login POSTs, want exactly 1", got)
	}
	if got := pb.Attempts(); got != 1 {
		t.Fatalf("Attempts = %d, want 1", got)
	}
	if res.PasswordAttempts != 1 {
		t.Fatalf("PasswordAttempts = %d, want 1", res.PasswordAttempts)
	}
	if res.PasswordErrors != 1 {
		t.Fatalf("PasswordErrors = %d, want 1", res.PasswordErrors)
	}
}

// TestBruteForceNoCloseOfClosedChannelPanic is the regression test for the
// original close(done) called from every successful goroutine.
func TestBruteForceMultipleMatchesDoesNotPanic(t *testing.T) {
	// This server accepts every password, so many workers "succeed" at once.
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if r.Method == nethttp.MethodGet {
			if _, err := r.Cookie("jsession"); err != nil {
				nethttp.SetCookie(w, &nethttp.Cookie{Name: "jsession", Value: "x", Path: "/"})
				w.Write([]byte(loginPage))
				return
			}
			w.Write([]byte(dashboardPage))
			return
		}
		w.Write([]byte(dashboardPage))
	}))
	defer srv.Close()

	pb := NewPasswordBruteforcer(testClient(t), 8)

	passwords := make([]string, 50)
	for i := range passwords {
		passwords[i] = fmt.Sprintf("pw%d", i)
	}

	// The old implementation panicked here with "close of closed channel".
	res, err := pb.BruteForcePassword(context.Background(), srv.URL, "admin", passwords)
	if err != nil {
		t.Fatalf("BruteForcePassword: %v", err)
	}
	if !res.PasswordValid {
		t.Fatal("expected a success")
	}
}

func TestBruteForceRespectsContextCancellation(t *testing.T) {
	fake := newFakeJoomla("admin", "never")
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	pb := NewPasswordBruteforcer(testClient(t), 2)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	passwords := make([]string, 10000)
	for i := range passwords {
		passwords[i] = fmt.Sprintf("pw%d", i)
	}

	start := time.Now()
	if _, err := pb.BruteForcePassword(ctx, srv.URL, "admin", passwords); err != nil &&
		!errors.Is(err, ErrAccountLockout) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unexpected error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("took %s; cancellation should have stopped the run", elapsed)
	}
}

func TestMatchLockout(t *testing.T) {
	tests := []struct {
		body   string
		status int
		want   bool
	}{
		{"Too many failed login attempts", 200, true},
		{"Your account has been temporarily locked", 200, true},
		{"Please complete the CAPTCHA", 200, true},
		{"", 429, true},
		{"Username and password do not match", 200, false},
		{"<html>normal login page</html>", 200, false},
	}

	for _, tc := range tests {
		got := matchLockout(tc.body, tc.status) != ""
		if got != tc.want {
			t.Errorf("matchLockout(%q, %d) = %v, want %v", tc.body, tc.status, got, tc.want)
		}
	}
}

func TestNormalizeTarget(t *testing.T) {
	tests := map[string]string{
		"https://a.tld/":    "https://a.tld",
		"https://a.tld///":  "https://a.tld",
		"http://a.tld/sub/": "http://a.tld/sub",
		"a.tld":             "http://a.tld",
		"  https://a.tld  ": "https://a.tld",
	}
	for in, want := range tests {
		if got := NormalizeTarget(in); got != want {
			t.Errorf("NormalizeTarget(%q) = %q, want %q", in, got, want)
		}
	}
}
