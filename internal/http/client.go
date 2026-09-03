package http

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

type ClientConfig struct {
	Timeout            time.Duration
	ProxyURL           string
	VerifySSL          bool
	UserAgent          string
	RateLimit          float64 // requests per second
	MaxConnections     int
	CustomHeaders      map[string]string
	FollowRedirects    bool
}

type Client struct {
	httpClient *http.Client
	limiter    *rate.Limiter
	config     ClientConfig
}

func NewClient(config ClientConfig) (*Client, error) {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.UserAgent == "" {
		config.UserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
	}
	if config.MaxConnections == 0 {
		config.MaxConnections = 10
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   config.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:       config.MaxConnections,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:    90 * time.Second,
	}

	// Handle proxy
	if config.ProxyURL != "" {
		proxyURL, err := url.Parse(config.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	// Handle SSL verification
	if !config.VerifySSL {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}

	if !config.FollowRedirects {
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	var limiter *rate.Limiter
	if config.RateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(config.RateLimit), 1)
	}

	return &Client{
		httpClient: httpClient,
		limiter:    limiter,
		config:     config,
	}, nil
}

type Response struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

func (c *Client) Get(targetURL string) (*Response, error) {
	return c.Do("GET", targetURL, nil, nil)
}

func (c *Client) Post(targetURL string, data []byte, contentType string) (*Response, error) {
	return c.Do("POST", targetURL, data, map[string]string{"Content-Type": contentType})
}

func (c *Client) Do(method string, targetURL string, body []byte, headers map[string]string) (*Response, error) {
	// Rate limiting
	if c.limiter != nil {
		c.limiter.Wait(nil)
	}

	req, err := http.NewRequest(method, targetURL, nil)
	if err != nil {
		return nil, err
	}

	// Set body if present
	if body != nil && len(body) > 0 {
		req.Body = io.NopCloser(strings.NewReader(string(body)))
		req.ContentLength = int64(len(body))
	}

	// Set default User-Agent
	req.Header.Set("User-Agent", c.config.UserAgent)

	// Set custom headers
	for key, value := range c.config.CustomHeaders {
		req.Header.Set(key, value)
	}

	// Override with request-specific headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       respBody,
	}, nil
}

func (r *Response) GetHeader(key string) string {
	return r.Headers.Get(key)
}

func (r *Response) String() string {
	return string(r.Body)
}
