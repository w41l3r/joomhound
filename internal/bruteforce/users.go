package bruteforce

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/w41l3r/joomhound/internal/http"
	"github.com/w41l3r/joomhound/internal/models"
)

// UserEnumerator discovers valid Joomla usernames.
type UserEnumerator struct {
	client  *http.Client
	threads int

	// OnFound is called for each confirmed user.
	OnFound func(models.User)
	// OnMessage reports method availability and warnings.
	OnMessage func(string)
}

// NewUserEnumerator creates an enumerator.
func NewUserEnumerator(client *http.Client, threads int) *UserEnumerator {
	if threads <= 0 {
		threads = 10
	}
	return &UserEnumerator{client: client, threads: threads}
}

func (ue *UserEnumerator) logf(format string, args ...any) {
	if ue.OnMessage != nil {
		ue.OnMessage(fmt.Sprintf(format, args...))
	}
}

// registrationOracle captures how the target responds to a username that is
// guaranteed NOT to exist. Every positive result must differ from this
// baseline, otherwise it is not evidence of anything.
//
// This replaces the previous logic, which reported a user as existing
// whenever the response contained "Invalid username or password" - a message
// Joomla returns for *every* failed login by design. That made the enumerator
// return every candidate as a valid user.
type registrationOracle struct {
	usable   bool
	status   int
	bodyHash string
}

// EnumerateUsers probes each candidate username using whichever methods the
// target actually supports.
func (ue *UserEnumerator) EnumerateUsers(ctx context.Context, targetURL string, usernames []string) ([]models.User, error) {
	base := NormalizeTarget(targetURL)

	if len(usernames) == 0 {
		return nil, nil
	}

	// Probe which techniques are viable before spending the wordlist.
	apiUsable := ue.probeAPI(ctx, base)
	oracle := ue.buildRegistrationOracle(ctx, base)

	if !apiUsable && !oracle.usable {
		ue.logf("[-] no reliable user-enumeration vector available on this target " +
			"(public API disabled and registration validation not discriminating); skipping")
		return nil, nil
	}
	if apiUsable {
		ue.logf("[+] user enumeration via public Joomla API is available")
	}
	if oracle.usable {
		ue.logf("[+] user enumeration via registration validation is available")
	}

	var (
		mu  sync.Mutex
		out []models.User
		wg  sync.WaitGroup
	)
	sem := make(chan struct{}, ue.threads)

	for _, name := range usernames {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		// Acquire before spawning: the old code launched one goroutine per
		// wordlist entry and only then blocked, so a large wordlist created
		// millions of goroutines at once.
		sem <- struct{}{}

		go func(username string) {
			defer wg.Done()
			defer func() { <-sem }()

			var (
				found  bool
				userID int
				method string
			)

			if apiUsable {
				if id, ok := ue.viaAPI(ctx, base, username); ok {
					found, userID, method = true, id, "public-api"
				}
			}
			if !found && oracle.usable {
				if ok := ue.viaRegistration(ctx, base, username, oracle); ok {
					found, method = true, "registration-validation"
				}
			}

			if !found {
				return
			}

			u := models.User{
				Username: username,
				ID:       userID,
				Found:    true,
				Method:   method,
			}

			mu.Lock()
			out = append(out, u)
			mu.Unlock()

			if ue.OnFound != nil {
				ue.OnFound(u)
			}
		}(name)
	}

	wg.Wait()
	return out, ctx.Err()
}

// probeAPI checks whether the Joomla 4+ public web-services API answers
// unauthenticated user queries (it normally returns 401/403).
func (ue *UserEnumerator) probeAPI(ctx context.Context, base string) bool {
	resp, err := ue.client.Get(ctx, base+"/api/index.php/v1/users")
	if err != nil || resp.StatusCode != 200 {
		return false
	}
	var payload map[string]any
	if err := json.Unmarshal(resp.Body, &payload); err != nil {
		return false
	}
	_, ok := payload["data"]
	return ok
}

// viaAPI looks a username up through the public API.
func (ue *UserEnumerator) viaAPI(ctx context.Context, base, username string) (int, bool) {
	endpoint := fmt.Sprintf("%s/api/index.php/v1/users?filter[search]=%s",
		base, url.QueryEscape(username))

	resp, err := ue.client.Get(ctx, endpoint)
	if err != nil || resp.StatusCode != 200 {
		return 0, false
	}

	var payload struct {
		Data []struct {
			ID         json.Number `json:"id"`
			Attributes struct {
				Username string `json:"username"`
				Name     string `json:"name"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Body, &payload); err != nil {
		return 0, false
	}

	// The API's search is fuzzy, so require an exact username match rather
	// than accepting the first row (which the old code did).
	for _, d := range payload.Data {
		if strings.EqualFold(d.Attributes.Username, username) {
			id, _ := d.ID.Int64()
			return int(id), true
		}
	}
	return 0, false
}

// buildRegistrationOracle establishes the "username is free" baseline using
// random usernames that cannot exist.
func (ue *UserEnumerator) buildRegistrationOracle(ctx context.Context, base string) registrationOracle {
	var o registrationOracle

	first, ok := ue.registrationProbe(ctx, base, "jh"+randomToken(8))
	if !ok {
		return o
	}
	second, ok := ue.registrationProbe(ctx, base, "jh"+randomToken(8))
	if !ok {
		return o
	}

	// The endpoint is only a usable oracle if it is deterministic for
	// non-existent users. If two random names produce different responses,
	// the signal is noise and we must not use it.
	if first.status != second.status || first.bodyHash != second.bodyHash {
		return o
	}

	o.usable = true
	o.status = first.status
	o.bodyHash = first.bodyHash
	return o
}

type probeResult struct {
	status   int
	bodyHash string
}

// registrationProbe submits a username to Joomla's registration validation
// endpoint and normalizes the response for comparison.
func (ue *UserEnumerator) registrationProbe(ctx context.Context, base, username string) (probeResult, bool) {
	endpoint := base + "/index.php?option=com_users&task=registration.register&format=json"

	form := url.Values{
		"jform[username]":  {username},
		"jform[name]":      {username},
		"jform[email1]":    {username + "@example.invalid"},
		"jform[email2]":    {username + "@example.invalid"},
		"jform[password1]": {"Jh" + randomToken(8) + "!aA1"},
		"jform[password2]": {"Jh" + randomToken(8) + "!aA1"},
	}

	resp, err := ue.client.PostForm(ctx, endpoint, form)
	if err != nil {
		return probeResult{}, false
	}

	return probeResult{
		status:   resp.StatusCode,
		bodyHash: normalizeBody(resp.String(), username),
	}, true
}

// viaRegistration reports a username as existing when its response differs
// from the known "free username" baseline.
func (ue *UserEnumerator) viaRegistration(ctx context.Context, base, username string, o registrationOracle) bool {
	res, ok := ue.registrationProbe(ctx, base, username)
	if !ok {
		return false
	}
	return res.status != o.status || res.bodyHash != o.bodyHash
}

// normalizeBody strips the echoed username and volatile tokens so that two
// responses differing only by those values compare equal.
func normalizeBody(body, username string) string {
	b := strings.ToLower(body)
	b = strings.ReplaceAll(b, strings.ToLower(username), "{{u}}")
	// Drop 32-hex CSRF tokens and session ids, which change per request.
	b = reCSRFTokenAlt.ReplaceAllString(b, "{{token}}")

	// Collapse whitespace so formatting differences do not register.
	b = strings.Join(strings.Fields(b), " ")

	// Compare on length plus a coarse content signature rather than the full
	// body, to stay cheap for large pages.
	return fmt.Sprintf("%d:%s", len(b), truncateStr(b, 512))
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// EnumerateViaProfilePages walks numeric user IDs looking for exposed profile
// or contact pages. IDs are bounded and the range is validated so a typo
// cannot launch an unbounded scan.
func (ue *UserEnumerator) EnumerateViaProfilePages(ctx context.Context, targetURL string, startID, maxID int) ([]models.User, error) {
	base := NormalizeTarget(targetURL)

	if startID < 1 {
		startID = 1
	}
	if maxID < startID {
		return nil, fmt.Errorf("invalid ID range: %d-%d", startID, maxID)
	}
	if maxID-startID > 100000 {
		return nil, fmt.Errorf("ID range %d-%d too large (max 100000)", startID, maxID)
	}

	var (
		mu  sync.Mutex
		out []models.User
		wg  sync.WaitGroup
	)
	sem := make(chan struct{}, ue.threads)

	for id := startID; id <= maxID; id++ {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(userID int) {
			defer wg.Done()
			defer func() { <-sem }()

			endpoint := fmt.Sprintf("%s/index.php?option=com_contact&view=contact&id=%d", base, userID)
			resp, err := ue.client.Get(ctx, endpoint)
			if err != nil || resp.StatusCode != 200 {
				return
			}

			name := extractContactName(resp.String())
			if name == "" {
				return
			}

			u := models.User{Username: name, ID: userID, Found: true, Method: "contact-page"}

			mu.Lock()
			out = append(out, u)
			mu.Unlock()

			if ue.OnFound != nil {
				ue.OnFound(u)
			}
		}(id)
	}

	wg.Wait()
	return out, ctx.Err()
}

// extractContactName pulls a person's name from a com_contact page, ignoring
// error and "not found" pages.
func extractContactName(body string) string {
	m := reContactName.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	name := strings.TrimSpace(stripTags(m[1]))
	lower := strings.ToLower(name)
	for _, bad := range []string{"error", "not found", "not authorised", "forbidden", "404"} {
		if strings.Contains(lower, bad) {
			return ""
		}
	}
	if name == "" || len(name) > 120 {
		return ""
	}
	return name
}
