package bruteforce

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/w41l3r/joomhound/internal/http"
)

var (
	// reCSRFToken matches Joomla's per-session CSRF token, rendered as a
	// hidden input whose *name* is a 32-char hex digest and whose value is 1.
	//
	// Without this token Joomla rejects every login POST before it ever
	// checks the credentials, so a brute-force that omits it can only ever
	// report "no valid password" - regardless of the password used.
	reCSRFToken = regexp.MustCompile(`(?i)<input[^>]+type=["']hidden["'][^>]+name=["']([a-f0-9]{32})["'][^>]+value=["']1["']`)
	// reCSRFTokenAlt handles the reversed attribute order.
	reCSRFTokenAlt = regexp.MustCompile(`(?i)<input[^>]+name=["']([a-f0-9]{32})["'][^>]+value=["']1["']`)
	// reCSRFTokenJS matches the token when exposed via Joomla.getOptions.
	reCSRFTokenJS = regexp.MustCompile(`(?i)["']csrf\.token["']\s*:\s*["']([a-f0-9]{32})["']`)

	// reLoginForm identifies a rendered Joomla login form.
	reLoginForm = regexp.MustCompile(`(?i)name=["']passwd["']`)

	// reAdminSuccess matches markers that only appear once authenticated in
	// the administrator backend.
	reAdminSuccess = regexp.MustCompile(`(?i)(option=com_cpanel|task=logout|com_login\.logout|id=["']sidebarmenu["']|class=["'][^"']*header-logout)`)

	// reContactName matches the page heading of a com_contact page.
	reContactName = regexp.MustCompile(`(?is)<h[12][^>]*(?:class=["'][^"']*contact[^"']*["'])?[^>]*>(.{1,200}?)</h[12]>`)

	// reTag strips HTML tags.
	reTag = regexp.MustCompile(`<[^>]*>`)
)

// stripTags removes HTML tags from a fragment.
func stripTags(s string) string {
	return strings.TrimSpace(reTag.ReplaceAllString(s, ""))
}

// NormalizeTarget trims trailing slashes and adds a scheme if missing.
func NormalizeTarget(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return t
	}
	if !strings.HasPrefix(t, "http://") && !strings.HasPrefix(t, "https://") {
		t = "http://" + t
	}
	return strings.TrimRight(t, "/")
}

// extractCSRFToken pulls the Joomla CSRF token out of an HTML page.
func extractCSRFToken(body string) (string, bool) {
	for _, re := range []*regexp.Regexp{reCSRFToken, reCSRFTokenAlt, reCSRFTokenJS} {
		if m := re.FindStringSubmatch(body); len(m) > 1 {
			return m[1], true
		}
	}
	return "", false
}

// adminSession is one authenticated-login attempt context: its own cookie jar
// and its own CSRF token, obtained from a fresh GET of the login page.
type adminSession struct {
	client   *http.Client
	loginURL string
	token    string
}

// newAdminSession fetches the administrator login page, capturing the session
// cookie and CSRF token needed for a login POST to be accepted.
func newAdminSession(ctx context.Context, base *http.Client, targetURL string) (*adminSession, error) {
	sessionClient, err := base.NewSession()
	if err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}

	loginURL := NormalizeTarget(targetURL) + "/administrator/index.php"

	resp, err := sessionClient.Get(ctx, loginURL)
	if err != nil {
		return nil, fmt.Errorf("fetching login page: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("login page returned status %d", resp.StatusCode)
	}

	token, ok := extractCSRFToken(resp.String())
	if !ok {
		// Not fatal: some deployments render the form via JS. The caller can
		// still attempt a tokenless POST, it just usually fails.
		token = ""
	}

	return &adminSession{
		client:   sessionClient,
		loginURL: loginURL,
		token:    token,
	}, nil
}

// randomToken returns a random hex string, used to build usernames and emails
// that are guaranteed not to exist on the target.
func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is effectively impossible; degrade rather than
		// crash a running engagement.
		return "jh0000000000"
	}
	return hex.EncodeToString(b)
}

// base64Return builds the base64 "return" parameter Joomla expects.
func base64Return(path string) string {
	return base64.StdEncoding.EncodeToString([]byte(path))
}
