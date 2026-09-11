package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// Defaults applied when a ClientConfig field is left zero.
const (
	DefaultTimeout     = 20 * time.Second
	DefaultMaxBodySize = 8 << 20 // 8 MiB - bounds memory per response
	DefaultRateLimit   = 10.0
	DefaultMaxRetries  = 2
)

// allowedProxySchemes is the whitelist of proxy schemes we accept. Anything
// else (file://, gopher://, an empty scheme, ...) is rejected up front instead
// of silently producing a client that cannot dial.
var allowedProxySchemes = map[string]bool{
	"http":   true,
	"https":  true,
	"socks5": true,
}

// Redirect policy errors are exported so callers and tests can distinguish a
// deliberate security refusal from an ordinary network failure.
var (
	ErrCrossHostRedirect = errors.New("cross-host redirect refused")
	ErrRedirectLimit     = errors.New("redirect limit exceeded")
)

// ClientConfig configures a Client.
type ClientConfig struct {
	Timeout   time.Duration
	ProxyURL  string
	VerifySSL bool
	UserAgent string

	// RateLimit is the sustained requests-per-second ceiling across the whole
	// client. Zero means unlimited.
	RateLimit float64
	// Burst is the token-bucket burst size. Defaults to ceil(RateLimit) so a
	// short spike is tolerated without breaking the sustained average.
	Burst int

	// MaxConnections bounds pooled connections. It should match the scan's
	// worker count, otherwise workers fight over too few sockets.
	MaxConnections int

	CustomHeaders   map[string]string
	FollowRedirects bool

	// MaxBodySize caps how much of a response body we buffer.
	MaxBodySize int64

	// MaxRetries is the number of retries after the first attempt for safe,
	// idempotent requests that hit transient failures (network error, 429,
	// 5xx). Requests with side effects, including POST, are never retried.
	MaxRetries     int
	RetryBaseDelay time.Duration

	// EnableCookies gives the client a cookie jar. Required for anything that
	// depends on a Joomla session (CSRF tokens, login).
	EnableCookies bool

	// Breaker configures the circuit breaker. Zero value = disabled.
	Breaker BreakerConfig
}

// Stats are the counters a Client accumulates. Read them with Client.Stats.
type Stats struct {
	Requests    int64
	Errors      int64
	Retries     int64
	RateLimited int64
	BytesRead   int64
}

// sharedStats is shared by the scan client and every isolated cookie session.
// Without shared counters, credential traffic disappeared from final reports
// because each password attempt is intentionally executed in a fresh Client.
type sharedStats struct {
	requests    atomic.Int64
	errors      atomic.Int64
	retries     atomic.Int64
	rateLimited atomic.Int64
	bytesRead   atomic.Int64
}

// Client is a rate-limited, retrying, circuit-broken HTTP client shared by all
// scan phases. It is safe for concurrent use.
type Client struct {
	httpClient *http.Client
	limiter    *rate.Limiter
	breaker    *CircuitBreaker
	config     ClientConfig
	stats      *sharedStats
}

// NewClient builds a Client from config, applying defaults and validating the
// proxy URL.
func NewClient(config ClientConfig) (*Client, error) {
	if config.Timeout <= 0 {
		config.Timeout = DefaultTimeout
	}
	if config.UserAgent == "" {
		config.UserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
	}
	if config.MaxConnections <= 0 {
		config.MaxConnections = 10
	}
	if config.MaxBodySize <= 0 {
		config.MaxBodySize = DefaultMaxBodySize
	}
	if config.MaxRetries < 0 {
		config.MaxRetries = 0
	}
	if config.RetryBaseDelay <= 0 {
		config.RetryBaseDelay = 250 * time.Millisecond
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   config.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		// Pool sizing must track the worker count: with the old hardcoded
		// MaxIdleConnsPerHost=2 every extra worker paid for a fresh TCP+TLS
		// handshake on every request.
		MaxIdleConns:          config.MaxConnections,
		MaxIdleConnsPerHost:   config.MaxConnections,
		MaxConnsPerHost:       config.MaxConnections * 2,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: config.Timeout,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}

	if config.ProxyURL != "" {
		proxyURL, err := url.Parse(config.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL %q: %w", config.ProxyURL, err)
		}
		if proxyURL.Host == "" {
			return nil, fmt.Errorf("invalid proxy URL %q: missing host (expected scheme://host:port)", config.ProxyURL)
		}
		if !allowedProxySchemes[strings.ToLower(proxyURL.Scheme)] {
			return nil, fmt.Errorf("unsupported proxy scheme %q: use http, https or socks5", proxyURL.Scheme)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	if !config.VerifySSL {
		// Intentional for pentest targets with self-signed certs. Callers are
		// expected to surface this to the operator.
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		}
	} else {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}

	if config.EnableCookies {
		jar, err := cookiejar.New(nil)
		if err != nil {
			return nil, fmt.Errorf("creating cookie jar: %w", err)
		}
		httpClient.Jar = jar
	}

	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if !config.FollowRedirects {
			return http.ErrUseLastResponse
		}
		if len(via) >= 10 {
			return ErrRedirectLimit
		}
		if len(via) > 0 && !strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname()) {
			return fmt.Errorf("%w: %s -> %s", ErrCrossHostRedirect,
				via[0].URL.Hostname(), req.URL.Hostname())
		}
		return nil
	}

	var limiter *rate.Limiter
	if config.RateLimit > 0 {
		burst := config.Burst
		if burst <= 0 {
			burst = int(config.RateLimit)
			if burst < 1 {
				burst = 1
			}
		}
		limiter = rate.NewLimiter(rate.Limit(config.RateLimit), burst)
	}

	return &Client{
		httpClient: httpClient,
		limiter:    limiter,
		breaker:    NewCircuitBreaker(config.Breaker),
		config:     config,
		stats:      &sharedStats{},
	}, nil
}

// NewSession returns a Client that shares this client's transport, rate
// limiter and circuit breaker but owns a fresh cookie jar. Use it whenever a
// request sequence needs its own Joomla session (a login attempt) without
// escaping the global rate limit.
func (c *Client) NewSession() (*Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("creating cookie jar: %w", err)
	}

	inner := &http.Client{
		Transport:     c.httpClient.Transport,
		Timeout:       c.httpClient.Timeout,
		CheckRedirect: c.httpClient.CheckRedirect,
		Jar:           jar,
	}

	// Login requests have side effects and must never inherit a retry budget.
	// Do also refuses to retry POST, but zeroing this budget protects the
	// session's preparatory and verification requests from multiplying a
	// credential attempt when the target starts throttling.
	sessionConfig := c.config
	sessionConfig.MaxRetries = 0

	return &Client{
		httpClient: inner,
		limiter:    c.limiter, // shared on purpose
		breaker:    c.breaker, // shared on purpose
		config:     sessionConfig,
		stats:      c.stats, // aggregate login traffic in scan metadata
	}, nil
}

// Response is a fully-buffered HTTP response.
type Response struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	// FinalURL is the URL that actually served the response after redirects.
	FinalURL string
	// Truncated reports whether the body hit MaxBodySize.
	Truncated bool
	// Elapsed is the wall time of the successful attempt.
	Elapsed time.Duration
}

// Get issues a GET.
func (c *Client) Get(ctx context.Context, targetURL string) (*Response, error) {
	return c.Do(ctx, http.MethodGet, targetURL, nil, nil)
}

// PostForm issues a urlencoded POST.
func (c *Client) PostForm(ctx context.Context, targetURL string, form url.Values) (*Response, error) {
	return c.Do(ctx, http.MethodPost, targetURL, []byte(form.Encode()),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
}

// Post issues a POST with an explicit content type.
func (c *Client) Post(ctx context.Context, targetURL string, data []byte, contentType string) (*Response, error) {
	return c.Do(ctx, http.MethodPost, targetURL, data, map[string]string{"Content-Type": contentType})
}

// Do performs a request with rate limiting, circuit breaking and bounded
// retries. ctx cancels the whole operation, including waits.
func (c *Client) Do(ctx context.Context, method, targetURL string, body []byte, headers map[string]string) (*Response, error) {
	if ctx == nil {
		return nil, errors.New("http: nil context")
	}

	var lastErr error

	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		if attempt > 0 {
			c.stats.retries.Add(1)
			if err := sleepCtx(ctx, c.backoff(attempt, lastErr)); err != nil {
				return nil, err
			}
		}

		// Reject early if the target is already known to be failing.
		if err := c.breaker.Allow(); err != nil {
			return nil, err
		}

		// Rate limit. Wait honours ctx, unlike the previous Wait(nil) which
		// dereferenced a nil interface and panicked.
		if c.limiter != nil {
			if err := c.limiter.Wait(ctx); err != nil {
				return nil, fmt.Errorf("rate limiter: %w", err)
			}
		}

		resp, retryable, err := c.attempt(ctx, method, targetURL, body, headers)
		if err == nil {
			c.breaker.Success()
			return resp, nil
		}

		lastErr = err
		c.stats.errors.Add(1)
		c.breaker.Failure()

		// A cancelled context is never retryable.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !retryable || !isRetryableMethod(method) {
			return nil, err
		}
	}

	return nil, fmt.Errorf("after %d attempts: %w", c.config.MaxRetries+1, lastErr)
}

// attempt performs one HTTP round trip. retryable tells Do whether another
// attempt could plausibly succeed.
func (c *Client) attempt(ctx context.Context, method, targetURL string, body []byte, headers map[string]string) (resp *Response, retryable bool, err error) {
	var reader io.Reader
	if len(body) > 0 {
		// bytes.Reader gives net/http a working GetBody, so redirects and
		// internal retries can replay the body. Assigning req.Body by hand
		// (the previous approach) silently dropped the body on redirect.
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, reader)
	if err != nil {
		return nil, false, fmt.Errorf("building request: %w", err)
	}

	req.Header.Set("User-Agent", c.config.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	for k, v := range c.config.CustomHeaders {
		req.Header.Set(k, v)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	c.stats.requests.Add(1)

	httpResp, err := c.httpClient.Do(req)
	if err != nil {
		// Policy failures will not become valid on another attempt. Other
		// network-level failures may be retried when the method is safe.
		retryable := !errors.Is(err, ErrCrossHostRedirect) && !errors.Is(err, ErrRedirectLimit)
		return nil, retryable, fmt.Errorf("%s %s: %w", method, targetURL, err)
	}
	defer httpResp.Body.Close()

	// Bound the body: a hostile or misconfigured target must not be able to
	// exhaust our memory with an endless response.
	limited := io.LimitReader(httpResp.Body, c.config.MaxBodySize+1)
	respBody, readErr := io.ReadAll(limited)
	if readErr != nil {
		return nil, true, fmt.Errorf("reading body of %s: %w", targetURL, readErr)
	}

	truncated := false
	if int64(len(respBody)) > c.config.MaxBodySize {
		respBody = respBody[:c.config.MaxBodySize]
		truncated = true
		// Drain so the connection can be reused.
		_, _ = io.Copy(io.Discard, httpResp.Body)
	}
	c.stats.bytesRead.Add(int64(len(respBody)))

	out := &Response{
		StatusCode: httpResp.StatusCode,
		Headers:    httpResp.Header,
		Body:       respBody,
		FinalURL:   httpResp.Request.URL.String(),
		Truncated:  truncated,
		Elapsed:    time.Since(start),
	}

	switch {
	case httpResp.StatusCode == http.StatusTooManyRequests:
		c.stats.rateLimited.Add(1)
		return nil, true, &StatusError{StatusCode: httpResp.StatusCode, RetryAfter: parseRetryAfter(httpResp.Header)}
	case httpResp.StatusCode >= 500:
		return nil, true, &StatusError{StatusCode: httpResp.StatusCode, RetryAfter: parseRetryAfter(httpResp.Header)}
	}

	return out, false, nil
}

// backoff computes the delay before attempt n, honouring Retry-After when the
// server told us how long to wait.
func (c *Client) backoff(attempt int, lastErr error) time.Duration {
	var se *StatusError
	if errors.As(lastErr, &se) && se.RetryAfter > 0 {
		return se.RetryAfter
	}
	d := c.config.RetryBaseDelay << (attempt - 1)
	if max := 10 * time.Second; d > max {
		d = max
	}
	return d
}

// StatusError is returned for transient HTTP status codes. Do decides whether
// retrying is safe for the request method.
type StatusError struct {
	StatusCode int
	RetryAfter time.Duration
}

func (e *StatusError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("http status %d (retry after %s)", e.StatusCode, e.RetryAfter)
	}
	return fmt.Sprintf("http status %d", e.StatusCode)
}

func parseRetryAfter(h http.Header) time.Duration {
	v := h.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && secs >= 0 {
		if secs > 60 {
			secs = 60 // never let a target park us indefinitely
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			if d > time.Minute {
				d = time.Minute
			}
			return d
		}
	}
	return 0
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func isRetryableMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead:
		return true
	default:
		return false
	}
}

// Stats returns a snapshot of the client's counters.
func (c *Client) Stats() Stats {
	return Stats{
		Requests:    c.stats.requests.Load(),
		Errors:      c.stats.errors.Load(),
		Retries:     c.stats.retries.Load(),
		RateLimited: c.stats.rateLimited.Load(),
		BytesRead:   c.stats.bytesRead.Load(),
	}
}

// BreakerState exposes the circuit breaker state for reporting.
func (c *Client) BreakerState() BreakerState { return c.breaker.State() }

// BreakerTripped reports how many times the breaker opened during the scan.
func (c *Client) BreakerTripped() int { return c.breaker.Tripped() }

// CloseIdleConnections releases pooled sockets.
func (c *Client) CloseIdleConnections() { c.httpClient.CloseIdleConnections() }

// GetHeader returns a response header value.
func (r *Response) GetHeader(key string) string { return r.Headers.Get(key) }

// String returns the response body as a string.
func (r *Response) String() string { return string(r.Body) }
