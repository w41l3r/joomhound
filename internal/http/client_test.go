package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(t *testing.T, cfg ClientConfig) *Client {
	t.Helper()
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// TestRateLimiterDoesNotPanic is the regression test for the original
// c.limiter.Wait(nil) call. Passing a nil context dereferenced a nil
// interface inside x/time/rate, so every request panicked as soon as a rate
// limit was configured - which the scanner always did (RateLimit: 10.0).
func TestRateLimiterDoesNotPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c := newTestClient(t, ClientConfig{RateLimit: 100, Burst: 10})

	for i := 0; i < 3; i++ {
		resp, err := c.Get(context.Background(), srv.URL)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
	}
}

func TestContextCancellationStopsRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	c := newTestClient(t, ClientConfig{Timeout: 5 * time.Second})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := c.Get(ctx, srv.URL); err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("cancellation took %s, expected it to return promptly", elapsed)
	}
}

func TestPostBodyIsSent(t *testing.T) {
	var got atomic.Value

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		got.Store(string(buf))
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := newTestClient(t, ClientConfig{})

	body := "username=admin&passwd=secret"
	if _, err := c.Post(context.Background(), srv.URL, []byte(body), "application/x-www-form-urlencoded"); err != nil {
		t.Fatalf("Post: %v", err)
	}

	if v, _ := got.Load().(string); v != body {
		t.Fatalf("server received %q, want %q", v, body)
	}
}

// TestRetriesOnServerError verifies the retry path added to Do.
func TestRetriesOnServerError(t *testing.T) {
	var calls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("recovered"))
	}))
	defer srv.Close()

	c := newTestClient(t, ClientConfig{MaxRetries: 3, RetryBaseDelay: time.Millisecond})

	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if n := calls.Load(); n != 3 {
		t.Fatalf("server saw %d calls, want 3", n)
	}
	if stats := c.Stats(); stats.Retries != 2 {
		t.Fatalf("Retries = %d, want 2", stats.Retries)
	}
}

func TestRetryAfterIsHonoured(t *testing.T) {
	var calls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := newTestClient(t, ClientConfig{MaxRetries: 2, RetryBaseDelay: time.Millisecond})

	start := time.Now()
	if _, err := c.Get(context.Background(), srv.URL); err != nil {
		t.Fatalf("Get: %v", err)
	}

	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Fatalf("waited %s, expected to honour Retry-After: 1", elapsed)
	}
	if stats := c.Stats(); stats.RateLimited != 1 {
		t.Fatalf("RateLimited = %d, want 1", stats.RateLimited)
	}
}

// TestBodyIsBounded checks the io.LimitReader guard: an unbounded io.ReadAll
// let a hostile target exhaust scanner memory.
func TestBodyIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(strings.Repeat("A", 10000)))
	}))
	defer srv.Close()

	c := newTestClient(t, ClientConfig{MaxBodySize: 1024})

	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(resp.Body) != 1024 {
		t.Fatalf("body length = %d, want 1024", len(resp.Body))
	}
	if !resp.Truncated {
		t.Fatal("expected Truncated = true")
	}
}

func TestCookieJarPersistsSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("sess"); err != nil {
			http.SetCookie(w, &http.Cookie{Name: "sess", Value: "abc123", Path: "/"})
			w.Write([]byte("issued"))
			return
		}
		w.Write([]byte("returned"))
	}))
	defer srv.Close()

	c := newTestClient(t, ClientConfig{EnableCookies: true})

	if _, err := c.Get(context.Background(), srv.URL); err != nil {
		t.Fatalf("first Get: %v", err)
	}
	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if got := resp.String(); got != "returned" {
		t.Fatalf("body = %q, want %q (cookie was not persisted)", got, "returned")
	}
}

// TestNewSessionIsolatesCookies confirms each login attempt gets a clean jar.
func TestNewSessionIsolatesCookies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("sess"); err != nil {
			http.SetCookie(w, &http.Cookie{Name: "sess", Value: "x", Path: "/"})
			w.Write([]byte("issued"))
			return
		}
		w.Write([]byte("returned"))
	}))
	defer srv.Close()

	c := newTestClient(t, ClientConfig{EnableCookies: true})
	if _, err := c.Get(context.Background(), srv.URL); err != nil {
		t.Fatalf("Get: %v", err)
	}

	sess, err := c.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	resp, err := sess.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("session Get: %v", err)
	}
	if got := resp.String(); got != "issued" {
		t.Fatalf("body = %q, want %q (session should start with no cookies)", got, "issued")
	}
}

func TestProxyValidation(t *testing.T) {
	tests := []struct {
		name    string
		proxy   string
		wantErr bool
	}{
		{"valid http", "http://127.0.0.1:8080", false},
		{"valid socks5", "socks5://127.0.0.1:1080", false},
		{"unsupported scheme", "gopher://127.0.0.1:70", true},
		{"missing host", "http://", true},
		{"no scheme", "127.0.0.1:8080", true},
		{"garbage", "://::::", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewClient(ClientConfig{ProxyURL: tc.proxy})
			if tc.wantErr && err == nil {
				t.Fatalf("NewClient(%q) = nil error, want error", tc.proxy)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("NewClient(%q) = %v, want nil", tc.proxy, err)
			}
		})
	}
}

// TestCircuitBreakerOpens verifies the scan stops hammering a dead target.
func TestCircuitBreakerOpens(t *testing.T) {
	var calls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(500)
	}))
	defer srv.Close()

	c := newTestClient(t, ClientConfig{
		MaxRetries:     0,
		RetryBaseDelay: time.Millisecond,
		Breaker: BreakerConfig{
			Enabled:          true,
			FailureThreshold: 3,
			OpenTimeout:      time.Minute,
			HalfOpenProbes:   1,
		},
	})

	ctx := context.Background()
	var lastErr error
	for i := 0; i < 10; i++ {
		_, lastErr = c.Get(ctx, srv.URL)
	}

	if !errors.Is(lastErr, ErrCircuitOpen) {
		t.Fatalf("last error = %v, want ErrCircuitOpen", lastErr)
	}
	if n := calls.Load(); n > 4 {
		t.Fatalf("target received %d requests; breaker should have stopped it near 3", n)
	}
}
